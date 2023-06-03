package examples

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
	"github.com/rayuruno/ltirun/lti"
	"github.com/valyala/fastjson"
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

	// custom config example
	app.Get("/proctoring/.well-known/openid_configuration", func(c *fiber.Ctx) error {
		c.Set("Content-Type", "application/json")
		return c.JSON(lti.Tool{
			ClientName: "Proctoring provider",
			LtiTool: lti.LtiTool{
				Messages: []lti.LtiMessage{
					{
						Type:  "LtiStartProctoring",
						Label: "Start Proctoring",
						Roles: []string{
							"https://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
							"https://purl.imsglobal.org/vocab/lis/v2/membership#Student",
						},
					},
					{
						Type:  "LtiEndAssesment",
						Label: "Stop Proctoring",
						Roles: []string{
							"https://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
							"https://purl.imsglobal.org/vocab/lis/v2/membership#Student",
						},
					},
				},
			},
		})
	})
	app.Post("/proctoring/lti/launch", func(c *fiber.Ctx) error {
		token := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
		if token == "" {
			return fiber.ErrUnauthorized
		}
		mtype := fastjson.GetString(c.Body(), "https://purl.imsglobal.org/spec/lti/claim/message_type")
		switch mtype {
		case "LtiStartProctoring":
			return c.Render("views/examples/start-proctoring", fiber.Map{
				"Token":            token,
				"Data":             string(c.Body()),
				"EndAssessmentUri": c.BaseURL() + prefix + "/proctoring/end-assessment",
			}, "views/examples/layout")
		case "LtiResourceLinkRequest":
			return c.Render("views/examples/start-proctoring-fallback", fiber.Map{
				"Token": token,
				"Data":  string(c.Body()),
			}, "views/examples/layout")
		default:
			return c.SendString("unknown message type")
		}

	})
	app.All("/proctoring/end-assessment", func(c *fiber.Ctx) error {
		return c.Render("views/examples/end-assessment", fiber.Map{"Sub": c.Query("sub")})
	})

	return app
}
