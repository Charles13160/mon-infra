package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/virtusia/mcp-suite/internal/api/middleware"
)

var version = "2.0.0"

func main() {
	// Niveau de log configurable via LOG_LEVEL (debug|info|warn|error) — défaut: info
	var logCfg zap.Config
	if os.Getenv("LOG_LEVEL") == "debug" {
		logCfg = zap.NewDevelopmentConfig()
	} else {
		logCfg = zap.NewProductionConfig()
	}
	switch os.Getenv("LOG_LEVEL") {
	case "warn":
		logCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		logCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	}
	log, _ := logCfg.Build()
	defer log.Sync()

	// ── Config depuis variables d'environnement ─────────────────
	masterURL    := getenv("MCP_MASTER_URL", "http://100.64.0.3:8082")
	licenseKey   := getenv("MCP_LICENSE_KEY", "")
	hostID       := getenv("MCP_HOST_ID", "unknown")
	port         := getenv("MCP_PORT", "8010")
	dockerHost   := getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	pubKeyPath   := getenv("MASTER_PUBKEY_PATH", "/srv/mcp-worker/config/master.pub")

	log.Info("MCP Worker démarrage",
		zap.String("host_id", hostID),
		zap.String("version", version),
		zap.String("master_url", masterURL),
	)

	// ── Fingerprint système (hash du hostname + interfaces réseau) ─
	fingerprint := buildFingerprint(hostID)

	// ── Middleware JWT (valide que les requêtes viennent du master) ─
	jwtAuth := middleware.NewMasterJWTAuth(pubKeyPath, log)

	// ── Register auprès du master ───────────────────────────────
	ctx := context.Background()
	if licenseKey != "" && masterURL != "" {
		masterPubKey, err := registerWithMaster(ctx, masterURL, licenseKey, hostID, fingerprint, log)
		if err != nil {
			log.Error("Echec register — worker démarre sans auth JWT (mode dégradé)",
				zap.Error(err))
		} else {
			if err := jwtAuth.UpdateKey(masterPubKey); err != nil {
				log.Error("Impossible de charger la clé publique du master", zap.Error(err))
			} else {
				log.Info("Clé publique master chargée — JWT validation active")
			}
		}
	} else {
		log.Warn("MCP_LICENSE_KEY vide — register ignoré, JWT validation désactivée")
	}

	// ── Heartbeat toutes les 30s ─────────────────────────────────
	if licenseKey != "" {
		go startHeartbeat(ctx, masterURL, licenseKey, hostID, log)
	}

	// ── Router MCP ───────────────────────────────────────────────
	mux := http.NewServeMux()

	// /health — public, pas de JWT requis
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"host_id": hostID,
			"version": version,
		})
	})

	// /mcp — protégé par JWT master
	mcpHandler := buildMCPHandler(dockerHost, hostID, log)
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))
		var probe struct{ Method string `json:"method"` }
		json.Unmarshal(body, &probe)
		if probe.Method == "tools/list" {
			r.Body = io.NopCloser(bytes.NewReader(body))
			mcpHandler.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		jwtAuth.Middleware(mcpHandler).ServeHTTP(w, r)
	})

	// ── Serveur HTTP ─────────────────────────────────────────────
	srv := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%s", port),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info("MCP Worker en écoute", zap.String("port", port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("erreur serveur HTTP", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Info("Arrêt gracieux...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
	log.Info("Worker arrêté")
}

// ── Register auprès du master ─────────────────────────────────────
func registerWithMaster(ctx context.Context, masterURL, licenseKey, hostID, fingerprint string, log *zap.Logger) (string, error) {
	// Récupérer les tools pour les envoyer au master
	tools := dockerTools()
	// Construire l'URL du worker depuis l'env ou dériver du masterURL
	workerPort := getenv("MCP_PORT", "8010")
	// Utiliser MCP_ADVERTISE_URL si défini, sinon construire depuis HOST_ID + port
	workerAdvertise := getenv("MCP_ADVERTISE_URL", "")
	var workerURL string
	if workerAdvertise != "" {
		workerURL = workerAdvertise
	} else {
		// Fallback : utiliser le hostID comme hostname (résolu via Tailscale DNS)
		workerURL = fmt.Sprintf("http://%s:%s/mcp", hostID, workerPort)
	}
	payload := map[string]interface{}{
		"host_id":        hostID,
		"fingerprint":    fingerprint,
		"worker_version": version,
		"worker_url":     workerURL,
		"domain":         "docker",
		"tools":          tools,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(masterURL, "/")+"/worker/register",
		bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", licenseKey)

	client := &http.Client{Timeout: 15 * time.Second}

	// Retry 3 fois avec backoff (le master peut démarrer après le worker)
	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		log.Warn("Register attempt failed, retrying...",
			zap.Int("attempt", attempt), zap.Error(err))
		time.Sleep(time.Duration(attempt*3) * time.Second)

		// Reconstruire la requête (body déjà consommé)
		req2, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(masterURL, "/")+"/worker/register",
			bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("X-License-Key", licenseKey)
		req = req2
	}
	if err != nil {
		return "", fmt.Errorf("register failed after 3 attempts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("master rejected register: HTTP %d", resp.StatusCode)
	}

	var result struct {
		HostID       string `json:"host_id"`
		MasterPubKey string `json:"master_public_key_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode register response: %w", err)
	}
	if result.MasterPubKey == "" {
		return "", fmt.Errorf("master returned empty public key")
	}

	log.Info("Worker enregistré auprès du master", zap.String("host_id", hostID))
	return result.MasterPubKey, nil
}

// ── Heartbeat ─────────────────────────────────────────────────────
func startHeartbeat(ctx context.Context, masterURL, licenseKey, hostID string, log *zap.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	client := &http.Client{Timeout: 5 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			url := fmt.Sprintf("%s/worker/heartbeat/%s",
				strings.TrimRight(masterURL, "/"), hostID)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("X-License-Key", licenseKey)
			resp, err := client.Do(req)
			if err != nil {
				log.Warn("Heartbeat failed", zap.Error(err))
				continue
			}
			resp.Body.Close()
		}
	}
}

// ── Handler MCP JSON-RPC ──────────────────────────────────────────
// Proxy vers le worker MCP Docker existant sur le même host
// Le worker actuel tourne sur :8010 — on wrappe son comportement
func buildMCPHandler(dockerHost, hostID string, log *zap.Logger) http.Handler {
	// Client Docker HTTP direct
	dockerClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				if strings.HasPrefix(dockerHost, "tcp://") {
					return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(dockerHost, "tcp://"))
				}
				return (&net.Dialer{}).DialContext(ctx, "unix", strings.TrimPrefix(dockerHost, "unix://"))
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      interface{}     `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPCError(w, nil, -32700, "parse error")
			return
		}

		switch req.Method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]string{
						"name":    "mcp-worker-" + hostID,
						"version": version,
					},
					"capabilities": map[string]interface{}{
						"tools": map[string]bool{"listChanged": false},
					},
				},
			})

		case "tools/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"tools": dockerTools(),
				},
			})

		case "tools/call":
			var params struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				writeRPCError(w, req.ID, -32602, "invalid params")
				return
			}
			// tokens_in = taille du payload (action + arguments)
			paramsBytes, _ := json.Marshal(params.Arguments)
			tokensIn := len(params.Name) + len(paramsBytes)

			result, err := executeDockerTool(r.Context(), dockerClient, dockerHost, params.Name, params.Arguments, log)
			if err != nil {
				writeRPCError(w, req.ID, -32000, err.Error())
				return
			}

			// tokens_out = taille de la réponse
			tokensOut := len(result)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"content": []map[string]string{
						{"type": "text", "text": result},
					},
					"tokens_in":  tokensIn,
					"tokens_out": tokensOut,
				},
			})

		default:
			writeRPCError(w, req.ID, -32601, "method not found")
		}
	})
}

// ── Outils Docker disponibles ─────────────────────────────────────
func dockerTools() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "docker_ps",
			"description": "Liste les containers Docker en cours d'exécution",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "docker_logs",
			"description": "Récupère les logs d'un container Docker",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"container": map[string]string{"type": "string", "description": "Nom ou ID du container"},
					"tail":      map[string]string{"type": "string", "description": "Nombre de lignes (défaut: 100)"},
				},
				"required": []string{"container"},
			},
		},
		{
			"name":        "docker_inspect",
			"description": "Inspecte un container Docker",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"container": map[string]string{"type": "string", "description": "Nom ou ID du container"},
				},
				"required": []string{"container"},
			},
		},
		{
			"name":        "docker_restart",
			"description": "Redémarre un container Docker",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"container": map[string]string{"type": "string", "description": "Nom ou ID du container"},
				},
				"required": []string{"container"},
			},
		},
	}
}

// ── Exécution des outils Docker ───────────────────────────────────
func executeDockerTool(ctx context.Context, client *http.Client, dockerHost, tool string, args map[string]interface{}, log *zap.Logger) (string, error) {
	baseURL := "http://localhost"
	if strings.HasPrefix(dockerHost, "tcp://") {
		baseURL = "http://" + strings.TrimPrefix(dockerHost, "tcp://")
	}

	switch tool {
	case "docker_ps":
		resp, err := client.Get(baseURL + "/containers/json?all=true")
		if err != nil {
			return "", fmt.Errorf("docker ps failed: %w", err)
		}
		defer resp.Body.Close()
		var containers []map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&containers)
		var result []map[string]interface{}
		for _, c := range containers {
			names, _ := c["Names"].([]interface{})
			name := ""
			if len(names) > 0 {
				name = strings.TrimPrefix(fmt.Sprint(names[0]), "/")
			}
			result = append(result, map[string]interface{}{
				"name":   name,
				"image":  c["Image"],
				"state":  c["State"],
				"status": c["Status"],
			})
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return string(out), nil

	case "docker_logs":
		container := fmt.Sprint(args["container"])
		tail := "100"
		if t, ok := args["tail"].(string); ok && t != "" {
			tail = t
		}
		resp, err := client.Get(fmt.Sprintf("%s/containers/%s/logs?stdout=true&stderr=true&tail=%s", baseURL, container, tail))
		if err != nil {
			return "", fmt.Errorf("docker logs failed: %w", err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return buf.String(), nil

	case "docker_inspect":
		container := fmt.Sprint(args["container"])
		resp, err := client.Get(fmt.Sprintf("%s/containers/%s/json", baseURL, container))
		if err != nil {
			return "", fmt.Errorf("docker inspect failed: %w", err)
		}
		defer resp.Body.Close()
		var data interface{}
		json.NewDecoder(resp.Body).Decode(&data)
		out, _ := json.MarshalIndent(data, "", "  ")
		return string(out), nil

	case "docker_restart":
		container := fmt.Sprint(args["container"])
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/containers/%s/restart", baseURL, container), nil)
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("docker restart failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			return fmt.Sprintf("Container %s restarted", container), nil
		}
		return "", fmt.Errorf("docker restart returned HTTP %d", resp.StatusCode)

	default:
		return "", fmt.Errorf("unknown tool: %s", tool)
	}
}

// ── Helpers ───────────────────────────────────────────────────────
func writeRPCError(w http.ResponseWriter, id interface{}, code int, msg string) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": msg},
	})
}

func buildFingerprint(hostID string) string {
	ifaces, _ := net.Interfaces()
	h := sha256.New()
	h.Write([]byte(hostID))
	for _, iface := range ifaces {
		h.Write([]byte(iface.HardwareAddr.String()))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
