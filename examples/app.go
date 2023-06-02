package examples

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
	"github.com/rayuruno/ltirun/lti"
)

func New(views *html.Engine, hostname string) *fiber.App {
	app := fiber.New(fiber.Config{Views: views})
	prefix := "/examples"

	if hostname != "" {
		prefix = ""

		app.Use(func(c *fiber.Ctx) error {
			log.Println("HOSTCHECK", c.Hostname(), hostname)
			if c.Hostname() == hostname {
				return c.Next()
			}
			return fiber.ErrNotFound
		})
	}

	app.Post("/provider/lti/launch", func(c *fiber.Ctx) error {
		token := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if token == "" {
			return fiber.ErrUnauthorized
		}
		return c.Render("views/examples/service", fiber.Map{"Token": token, "Data": string(c.Body())}, "views/examples/layout")
	})

	app.Get("/custom/.well-known/openid_configuration", func(c *fiber.Ctx) error {
		c.Set("Content-Type", "application/json")
		return c.JSON(lti.Tool{
			ClientName: "custom client",
			LtiTool: lti.LtiTool{
				Messages: []lti.LtiMessage{
					{
						Type:          "LtiStartProctoring",
						TargetLinkUri: c.BaseURL() + prefix + "/custom/start-proctoring",
					},
					{
						Type:          "LtiEndAssesment",
						TargetLinkUri: c.BaseURL() + prefix + "/custom/end-assessment",
					},
				},
			},
		})
	})

	app.Post("/custom/start-proctoring", func(c *fiber.Ctx) error {
		token := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if token == "" {
			return fiber.ErrUnauthorized
		}
		return c.Render("views/examples/start-proctoring", fiber.Map{
			"Token":            token,
			"Data":             string(c.Body()),
			"EndAssessmentUri": c.BaseURL() + prefix + "/custom/end-assessment",
		}, "views/examples/layout")
	})
	app.All("/custom/end-assessment", func(c *fiber.Ctx) error {
		log.Printf("%#v \n %#v \n %#v \n %s", c.Context().QueryArgs().String(), c.Context().PostArgs().String(), c.GetReqHeaders(), string(c.Body()))
		return c.Render("views/examples/end-assessment", fiber.Map{"Sub": c.Query("sub")})
	})

	app.Post("/proctoring/lti/launch", func(c *fiber.Ctx) error {
		token := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if token == "" {
			return fiber.ErrUnauthorized
		}
		return c.Render("views/examples/start-proctoring", fiber.Map{
			"Token":            token,
			"Data":             string(c.Body()),
			"EndAssessmentUri": c.BaseURL() + prefix + "/proctoring/lti/end-assessment",
		}, "views/examples/layout")
	})
	app.All("/proctoring/lti/end-assessment", func(c *fiber.Ctx) error {
		log.Printf("%#v \n %#v \n %#v \n %s", c.Context().QueryArgs().String(), c.Context().PostArgs().String(), c.GetReqHeaders(), string(c.Body()))
		return c.Render("views/examples/end-assessment", fiber.Map{"Sub": c.Query("sub")})
	})

	return app
}
