package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/storage/redis/v2"
	"github.com/gofiber/template/html"
	"github.com/rayuruno/ltirun/examples"
	"github.com/rayuruno/ltirun/internal/keystore"
	"github.com/rayuruno/ltirun/lti"
	"github.com/rayuruno/ltirun/run"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"gitlab.com/proctorexam/go/env"
)

var (
	redisUrl     = env.Fetch("REDIS_URL", "redis://localhost:6379")
	examplesHost = env.Fetch("EXAMPLES_HOST", "")
)

//go:embed views
var viewsFS embed.FS

//go:embed static
var staticFS embed.FS

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	api := run.New(redis.New(redis.Config{URL: redisUrl}), keystore.New())
	views := html.NewFileSystem(http.FS(viewsFS), ".html")
	app := fiber.New(fiber.Config{
		Views:        views,
		ErrorHandler: errorHandler,
	})
	app.Use("/static", filesystem.New(filesystem.Config{
		Root:       http.FS(staticFS),
		MaxAge:     3600,
		PathPrefix: "static",
	}))
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("views/home", nil, "views/layout")
	})
	app.Get("/openid_configuration/*", recoverable(func(c *fiber.Ctx) error {
		c.Set("Content-Type", "application/json")
		providerUri := c.Params("*")
		t := new(lti.Tool)
		check(api.LoadToolConfig(c.BaseURL(), providerUri, t))
		b, err := json.MarshalIndent(t, "", "  ")
		check(err)
		return c.Send(b)
	}))
	app.Get("/jwks/*", recoverable(func(c *fiber.Ctx) error {
		c.Set("Content-Type", "application/json")
		jwks, err := api.JsonWebKeys(c.Params("*"))
		check(err)
		return c.Send(jwks)
	}))
	app.Get("/register/*", recoverable(func(c *fiber.Ctx) error {
		providerUri := c.Params("*")
		t := new(lti.Tool)
		err := api.LoadToolConfig(c.BaseURL(), providerUri, t)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		return c.Render("views/register", fiber.Map{
			"Platform": new(lti.Platform),
			"Tool":     t,
			"Link":     c.BaseURL() + "/openid_configuration/" + providerUri,
			"Error":    errMsg,
		}, "views/layout")
	}))
	app.Post("/register/*", recoverable(func(c *fiber.Ctx) error {
		providerUri := c.Params("*")
		p := new(lti.Platform)
		t := new(lti.Tool)
		r := new(lti.Registration)
		check(api.LoadToolConfig(c.BaseURL(), providerUri, t))
		p.Issuer = c.FormValue("issuer")
		p.JwksUri = c.FormValue("jwks_uri")
		p.TokenEndpoint = c.FormValue("token_endpoint")
		p.AuthorizationEndpoint = c.FormValue("authorization_endpoint")
		t.DeploymentId = c.FormValue("deployment_id")
		r.Tool = t
		r.ClientId = c.FormValue("client_id")
		err := api.StoreRegistration(providerUri, p, r)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		return c.Render("views/register", fiber.Map{
			"Platform":     p,
			"ClientId":     r.ClientId,
			"DeploymentId": r.DeploymentId,
			"Tool":         r.Tool,
			"Link":         c.BaseURL() + "/openid_configuration/" + providerUri,
			"Error":        errMsg,
		}, "views/layout")
	}))
	app.All("/connect/*", recoverable(func(c *fiber.Ctx) error {
		providerUri := c.Params("*")
		i := new(lti.RegistrationInit)
		p := new(lti.Platform)
		t := new(lti.Tool)
		r := new(lti.Registration)
		check(anyParser(c, i))
		check(api.GetPlatformConfig(i.Endpoint, i.Token, p))
		check(api.LoadToolConfig(c.BaseURL(), providerUri, t))
		check(api.PostToolConfig(p.RegistrationEndpoint, i.Token, t, r))
		check(api.StoreRegistration(providerUri, p, r))
		return c.Render("views/closer", nil)
	}))
	app.All("/login/*", recoverable(func(c *fiber.Ctx) error {
		i := new(lti.LoginInit)
		check(anyParser(c, i))
		location, err := api.Authn(c.Params("*"), i)
		check(err)
		return c.Redirect(location)
	}))
	app.All("/launch/*", recoverable(func(c *fiber.Ctx) error {
		a := new(lti.AuthenticateResponse)
		check(anyParser(c, a))
		s, err := api.Authz(c.Params("*"), a)
		check(err)
		b := ""
		check(api.Launch(s, &b))
		c.Set("Content-Type", fiber.MIMETextHTMLCharsetUTF8)
		return c.SendString(b)
	}))
	app.Post("/service/*", recoverable(func(c *fiber.Ctx) error {
		log.Debug().Any("head", c.GetReqHeaders()).Msg("service")
		if string(c.Context().Referer()) != c.BaseURL()+"/launch/"+c.Params("*") {
			return fiber.ErrUnauthorized
		}
		if c.Get("Sec-Fetch-Site") != "same-origin" {
			return fiber.ErrUnauthorized
		}
		sr := new(lti.ServiceRequest)
		a := new(lti.AccessToken)
		check(anyParser(c, sr))
		s, err := api.GetSession(jwksUri(c), bearer(c))
		check(err)
		check(api.GetAccessToken(s, sr, a))
		check(api.SendServiceRequest(a, sr))
		return c.SendStatus(200)
	}))
	app.Post("/jwt/*", recoverable(func(c *fiber.Ctx) error {
		if string(c.Context().Referer()) != c.BaseURL()+"/launch/"+c.Params("*") {
			return fiber.ErrUnauthorized
		}
		if c.Get("Sec-Fetch-Site") != "same-origin" {
			return fiber.ErrUnauthorized
		}
		s, err := api.GetSession(jwksUri(c), bearer(c))
		check(err)
		j, err := api.SignJWT(s, bytes.Clone(c.Body()))
		check(err)
		return c.SendString(j)
	}))

	if examplesHost != "" {
		app.Mount("/", examples.New(views, examplesHost))
	} else {
		app.Mount("/examples", examples.New(views, examplesHost))
	}

	app.Listen(":8080")
}

type errMsg string

func recoverable(h fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			switch err := recover().(type) {
			case errMsg:
				c.Status(400).SendString(string(err))
			case error:
				panic(err)
			}
		}()

		return h(c)
	}
}

func check(e error) {
	if e != nil {
		log.Error().Stack().Err(e).Msg("")
		panic(errMsg(e.Error()))
	}
}

func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
	}
	c.Set(fiber.HeaderContentType, c.GetRespHeader("Content-Type"))
	if strings.HasPrefix(c.GetRespHeader("Content-Type"), fiber.MIMEApplicationJSON) {
		return c.Status(code).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(code).SendString(err.Error())
}

func anyParser(c *fiber.Ctx, r any) error {
	switch {
	case c.Context().IsPost():
		return c.BodyParser(r)
	case c.Context().IsGet():
		return c.QueryParser(r)
	default:
		return fiber.ErrNotFound
	}
}

func jwksUri(c *fiber.Ctx) string {
	return c.BaseURL() + "/jwks/" + c.Params("*")
}

func bearer(c *fiber.Ctx) string {
	return strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
}
