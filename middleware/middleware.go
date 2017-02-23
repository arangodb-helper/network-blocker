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
		m.Post("/drop/from", handleAllFromDrop)
		m.Post("/reject/from", handleAllFromReject)
		m.Post("/accept/from", handleAllFromAccept)
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

func handleAllFromDrop(ctx *macaron.Context, s *service.Service) {
	ip := ctx.Query("ip")
	intf := ctx.Query("intf")
	if err := s.DropAllFrom(ip, intf); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		sendOK(ctx)
	}
}

func handleAllFromReject(ctx *macaron.Context, s *service.Service) {
	ip := ctx.Query("ip")
	intf := ctx.Query("intf")
	if err := s.RejectAllFrom(ip, intf); err != nil {
		sendError(ctx, http.StatusInternalServerError, err)
	} else {
		sendOK(ctx)
	}
}

func handleAllFromAccept(ctx *macaron.Context, s *service.Service) {
	ip := ctx.Query("ip")
	intf := ctx.Query("intf")
	if err := s.AcceptAllFrom(ip, intf); err != nil {
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
