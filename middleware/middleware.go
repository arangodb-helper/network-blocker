package middleware

import (
	"net/http"

	logging "github.com/op/go-logging"

	"github.com/arangodb/network-blocker/service"
	macaron "gopkg.in/macaron.v1"
)

func SetupRoutes(log *logging.Logger, s *service.Service) http.Handler {
	m := macaron.Classic()
	m.Use(macaron.Renderer())
	m.Map(log)
	m.Map(s)

	m.Get("/ping", handlePing)
	m.Group("/api/v1", func() {
		m.Get("/rules", handleRules)
		m.Post("/drop/tcp/:port", handleTcpDrop)
		m.Post("/reject/tcp/:port", handleTcpReject)
		m.Post("/accept/tcp/:port", handleTcpAccept)
	})

	return m
}

func handlePing(ctx *macaron.Context) {
	ctx.PlainText(200, []byte("OK"))
}

func handleTcpDrop(ctx *macaron.Context, s *service.Service) {
	port := ctx.ParamsInt("port")
	if err := s.DropTCP(port); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		sendOK(ctx)
	}
}

func handleTcpReject(ctx *macaron.Context, s *service.Service) {
	port := ctx.ParamsInt("port")
	if err := s.RejectTCP(port); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		sendOK(ctx)
	}
}

func handleTcpAccept(ctx *macaron.Context, s *service.Service) {
	port := ctx.ParamsInt("port")
	if err := s.AcceptTCP(port); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		sendOK(ctx)
	}
}

func handleRules(ctx *macaron.Context, s *service.Service) {
	if list, err := s.Rules(); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		data := map[string]interface{}{
			"rules": list,
		}
		ctx.JSON(http.StatusOK, data)
	}
}

func sendOK(ctx *macaron.Context) {
	data := map[string]string{
		"status": "ok",
	}
	ctx.JSON(http.StatusOK, data)
}

func sendError(ctx *macaron.Context, statusCode int, err error) {
	data := map[string]string{
		"error": err.Error(),
	}
	ctx.JSON(statusCode, data)
}
