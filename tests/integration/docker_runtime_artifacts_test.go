//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	dockerArtifactVersion = "integration-test"
	dockerArtifactCommit  = "0123456789abcdef"
	dockerArtifactDate    = "2026-11-02T00:00:00Z"

	dockerBuildTimeout   = 15 * time.Minute
	dockerCommandTimeout = 2 * time.Minute
)

type dockerEnginePlatform struct {
	OS   string `json:"Os"`
	Arch string `json:"Arch"`
}

type dockerImageDetails struct {
	ID           string `json:"Id"`
	OS           string `json:"Os"`
	Architecture string `json:"Architecture"`
	Config       struct {
		User        string   `json:"User"`
		Entrypoint  []string `json:"Entrypoint"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
}

func TestDockerRuntimeArtifacts(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged runtime artifact test requires Docker: %v", err)
	}

	engine := inspectDockerEnginePlatform(t)
	if engine.OS != "linux" {
		t.Fatalf("Docker engine OS = %q, want linux for the Linux runtime images", engine.OS)
	}
	if engine.Arch == "" {
		t.Fatal("Docker engine architecture is empty")
	}

	repositoryRoot := dockerArtifactRepositoryRoot(t)
	dockerfilePath := filepath.Join(repositoryRoot, "Dockerfile")
	unique := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	serverImage := "packmon-runtime-server-" + unique + ":test"
	cliImage := "packmon-runtime-cli-" + unique + ":test"
	for _, image := range []string{serverImage, cliImage} {
		if image != strings.ToLower(image) {
			t.Fatalf("generated Docker image tag %q is not lowercase", image)
		}
	}

	defer removeDockerArtifactImage(t, cliImage)
	defer removeDockerArtifactImage(t, serverImage)
	buildPackmonRuntimeImage(t, dockerfilePath, repositoryRoot, "server", serverImage)
	buildPackmonRuntimeImage(t, dockerfilePath, repositoryRoot, "cli", cliImage)

	serverDetails := inspectDockerImage(t, serverImage)
	cliDetails := inspectDockerImage(t, cliImage)
	assertDockerRuntimeImage(t, serverImage, serverDetails, engine, "packmon", []string{"packmon-server"})
	assertDockerRuntimeImage(t, cliImage, cliDetails, engine, "packmon", []string{"packmon"})

	assertDockerVersionOutput(t, serverImage, "packmon-server", serverDetails)
	assertDockerVersionOutput(t, cliImage, "packmon", cliDetails)
	assertDockerUser(t, serverImage)
	assertDockerUser(t, cliImage)

	assertDockerAPKPackages(t, serverImage, []string{
		"ca-certificates=20261020-r0",
		"git=2.54.0-r0",
		"tzdata=2026e-r0",
	})
	assertDockerAPKPackages(t, cliImage, []string{
		"ca-certificates=20261020-r0",
		"tzdata=2026e-r0",
	})
	assertDockerAPKPackageAbsent(t, cliImage, "git")

	for _, image := range []string{serverImage, cliImage} {
		assertDockerFileMatches(t, image, "/usr/share/doc/packmon/LICENSE", filepath.Join(repositoryRoot, "LICENSE"))
		assertDockerFileMatches(t, image, "/usr/share/doc/packmon/SECURITY.md", filepath.Join(repositoryRoot, "SECURITY.md"))
	}

	if serverDetails.Config.Healthcheck == nil {
		t.Fatal("server image has no configured healthcheck")
	}
	healthTest := serverDetails.Config.Healthcheck.Test
	if len(healthTest) != 2 || healthTest[0] != "CMD-SHELL" || healthTest[1] == "" {
		t.Fatalf("server healthcheck test = %#v, want exactly [CMD-SHELL <non-empty command>]", healthTest)
	}
	assertDockerHealthcheckExecution(t, serverImage, unique, healthTest[1])
}

func inspectDockerEnginePlatform(t *testing.T) dockerEnginePlatform {
	t.Helper()

	output := runDockerCommand(t, dockerCommandTimeout, "inspect Docker engine platform", "version", "--format", "{{json .Server}}")
	var platform dockerEnginePlatform
	if err := json.Unmarshal(output, &platform); err != nil {
		t.Fatalf("decode Docker engine platform: %v", err)
	}
	return platform
}

func dockerArtifactRepositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve runtime artifact test source path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("repository root = %q, want absolute path", root)
	}
	return root
}

func buildPackmonRuntimeImage(t *testing.T, dockerfilePath, contextPath, target, image string) {
	t.Helper()

	if !filepath.IsAbs(dockerfilePath) || !filepath.IsAbs(contextPath) {
		t.Fatalf("Docker build paths must be absolute: dockerfile=%q context=%q", dockerfilePath, contextPath)
	}
	args := []string{
		"build",
		"--file", dockerfilePath,
		"--target", target,
		"--tag", image,
		"--build-arg", "VERSION=" + dockerArtifactVersion,
		"--build-arg", "COMMIT=" + dockerArtifactCommit,
		"--build-arg", "DATE=" + dockerArtifactDate,
		contextPath,
	}
	assertNoDockerPullArgument(t, args)
	runDockerCommand(t, dockerBuildTimeout, "build Packmon "+target+" runtime image", args...)
}

func inspectDockerImage(t *testing.T, image string) dockerImageDetails {
	t.Helper()

	output := runDockerCommand(t, dockerCommandTimeout, "inspect Docker runtime image", "image", "inspect", image)
	var details []dockerImageDetails
	if err := json.Unmarshal(output, &details); err != nil {
		t.Fatalf("decode Docker image inspection: %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("Docker image inspection returned %d records, want 1", len(details))
	}
	return details[0]
}

func assertDockerRuntimeImage(t *testing.T, image string, details dockerImageDetails, engine dockerEnginePlatform, user string, entrypoint []string) {
	t.Helper()

	if details.ID == "" {
		t.Fatalf("Docker image %s has an empty ID", image)
	}
	if details.OS != engine.OS || details.Architecture != engine.Arch {
		t.Fatalf("Docker image %s platform = %s/%s, want engine platform %s/%s", image, details.OS, details.Architecture, engine.OS, engine.Arch)
	}
	if details.Config.User != user {
		t.Fatalf("Docker image %s Config.User = %q, want %q", image, details.Config.User, user)
	}
	if !equalStrings(details.Config.Entrypoint, entrypoint) {
		t.Fatalf("Docker image %s Config.Entrypoint = %#v, want %#v", image, details.Config.Entrypoint, entrypoint)
	}
}

func assertDockerVersionOutput(t *testing.T, image, binary string, details dockerImageDetails) {
	t.Helper()

	output := runDockerCommand(t, dockerCommandTimeout, "run Docker runtime version command", "run", "--rm", image, "version")
	want := fmt.Sprintf("%s %s (%s) built %s %s/%s\n", binary, dockerArtifactVersion, dockerArtifactCommit, dockerArtifactDate, details.OS, details.Architecture)
	if string(output) != want {
		t.Fatalf("Docker image %s version output = %q, want %q", image, output, want)
	}
}

func assertDockerUser(t *testing.T, image string) {
	t.Helper()

	output := runDockerCommand(t, dockerCommandTimeout, "run Docker runtime identity command", "run", "--rm", "--entrypoint", "id", image, "-un")
	if string(output) != "packmon\n" {
		t.Fatalf("Docker image %s runtime user = %q, want packmon", image, output)
	}
}

func assertDockerAPKPackages(t *testing.T, image string, packages []string) {
	t.Helper()

	for _, apkPackage := range packages {
		runDockerCommand(t, dockerCommandTimeout, "verify exact APK package version in "+image, "run", "--rm", "--entrypoint", "apk", image, "info", "--exists", apkPackage)
	}
}

func assertDockerAPKPackageAbsent(t *testing.T, image, apkPackage string) {
	t.Helper()

	output, err := tryDockerCommand(t, dockerCommandTimeout, "run", "--rm", "--entrypoint", "apk", image, "info", "--exists", apkPackage)
	if err == nil {
		t.Fatalf("Docker image %s unexpectedly contains APK package %q; output: %s", image, apkPackage, output)
	}
	if exitCode, ok := commandExitCode(err); !ok || exitCode != 1 {
		t.Fatalf("check absent APK package %q in Docker image %s: %v\n%s", apkPackage, image, err, output)
	}
}

func assertDockerFileMatches(t *testing.T, image, imagePath, sourcePath string) {
	t.Helper()

	want, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read source artifact %s: %v", filepath.Base(sourcePath), err)
	}
	got := runDockerCommand(t, dockerCommandTimeout, "read packaged "+filepath.Base(sourcePath)+" from "+image, "run", "--rm", "--entrypoint", "cat", image, imagePath)
	if string(got) != string(want) {
		t.Fatalf("Docker image %s artifact %s does not byte-match the repository source", image, imagePath)
	}
}

func assertDockerHealthcheckExecution(t *testing.T, serverImage, unique, healthCommand string) {
	t.Helper()

	fixtureDir := t.TempDir()
	fixtureSource := filepath.Join(fixtureDir, "main.go")
	fixtureDockerfile := filepath.Join(fixtureDir, "Dockerfile")
	if err := os.WriteFile(fixtureSource, []byte(dockerHealthFixtureSource), 0o600); err != nil {
		t.Fatalf("write Docker health fixture source: %v", err)
	}
	dockerfile := fmt.Sprintf(`ARG SERVER_IMAGE
FROM %s AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /fixture main.go
FROM ${SERVER_IMAGE}
COPY --from=build /fixture /fixture
ENTRYPOINT ["/fixture"]
`, dockerHealthFixtureBuilderImage)
	if err := os.WriteFile(fixtureDockerfile, []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Docker health fixture Dockerfile: %v", err)
	}
	if !filepath.IsAbs(fixtureDockerfile) || !filepath.IsAbs(fixtureDir) {
		t.Fatalf("Docker health fixture build paths must be absolute: dockerfile=%q context=%q", fixtureDockerfile, fixtureDir)
	}

	fixtureImage := "packmon-runtime-health-" + unique + ":test"
	defer removeDockerArtifactImage(t, fixtureImage)
	args := []string{
		"build",
		"--file", fixtureDockerfile,
		"--tag", fixtureImage,
		"--build-arg", "SERVER_IMAGE=" + serverImage,
		fixtureDir,
	}
	assertNoDockerPullArgument(t, args)
	runDockerCommand(t, dockerBuildTimeout, "build Docker health fixture image", args...)

	cases := []struct {
		name        string
		fixtureArgs []string
		environment []string
		wantOK      bool
	}{
		{name: "HTTP default port", fixtureArgs: []string{"-port=8080"}, wantOK: true},
		{name: "HTTP custom port", fixtureArgs: []string{"-port=18080"}, environment: []string{"PACKMON_SERVER_PORT=18080"}, wantOK: true},
		{name: "HTTPS flags", fixtureArgs: []string{"-port=18443", "-tls"}, environment: []string{"PACKMON_SERVER_PORT=18443", "PACKMON_TLS_CERT_FILE=/fixture-cert", "PACKMON_TLS_KEY_FILE=/fixture-key"}, wantOK: true},
		{name: "readiness 503", fixtureArgs: []string{"-port=18083", "-status=503"}, environment: []string{"PACKMON_SERVER_PORT=18083"}, wantOK: false},
		{name: "server unavailable", fixtureArgs: []string{"-idle"}, environment: []string{"PACKMON_SERVER_PORT=18084"}, wantOK: false},
	}

	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			container := fmt.Sprintf("packmon-runtime-health-%s-%d", unique, index)
			marker := "/tmp/fixture-ready"
			runArgs := []string{"run", "--detach", "--rm", "--name", container}
			for _, environment := range testCase.environment {
				runArgs = append(runArgs, "--env", environment)
			}
			runArgs = append(runArgs, fixtureImage, "-ready="+marker)
			runArgs = append(runArgs, testCase.fixtureArgs...)
			t.Cleanup(func() { removeDockerArtifactContainer(t, container) })
			runDockerCommand(t, dockerCommandTimeout, "start Docker health fixture", runArgs...)
			waitForDockerFixture(t, container, marker)

			output, err := tryDockerCommand(t, dockerCommandTimeout, "exec", container, "/bin/sh", "-c", healthCommand)
			if testCase.wantOK && err != nil {
				logDockerFixtureDiagnostics(t, container)
				t.Fatalf("healthcheck command failed for %s: %v\n%s", testCase.name, err, output)
			}
			if !testCase.wantOK {
				if err == nil {
					t.Fatalf("healthcheck command unexpectedly succeeded for %s", testCase.name)
				}
				if exitCode, ok := commandExitCode(err); !ok || exitCode != 1 {
					logDockerFixtureDiagnostics(t, container)
					t.Fatalf("healthcheck command for %s failed with an unexpected status: %v\n%s", testCase.name, err, output)
				}
			}
		})
	}
}

func waitForDockerFixture(t *testing.T, container, marker string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := tryDockerCommand(t, 5*time.Second, "exec", container, "test", "-f", marker); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logDockerFixtureDiagnostics(t, container)
	t.Fatal("Docker health fixture did not become ready within 30s")
}

func logDockerFixtureDiagnostics(t *testing.T, container string) {
	t.Helper()

	if output, err := tryDockerCommand(t, 10*time.Second, "inspect", "--format", "{{json .State}}", container); err == nil {
		t.Logf("Docker health fixture state: %s", output)
	}
	if output, err := tryDockerCommand(t, 10*time.Second, "logs", container); err == nil && len(output) > 0 {
		t.Logf("Docker health fixture logs:\n%s", output)
	}
}

func runDockerCommand(t *testing.T, timeout time.Duration, description string, args ...string) []byte {
	t.Helper()

	output, err := tryDockerCommand(t, timeout, args...)
	if err != nil {
		t.Fatalf("%s: %v\n%s", description, err, output)
	}
	return output
}

func tryDockerCommand(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, timeout, "docker", args...)
	defer cancel()
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("Docker command timed out after %s", timeout)
	}
	return output, err
}

func commandExitCode(err error) (int, bool) {
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return 0, false
	}
	return exitError.ExitCode(), true
}

func assertNoDockerPullArgument(t *testing.T, args []string) {
	t.Helper()

	for _, arg := range args {
		if arg == "--pull" || strings.HasPrefix(arg, "--pull=") {
			t.Fatalf("Docker build arguments unexpectedly request a pull: %#v", args)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func removeDockerArtifactContainer(t *testing.T, container string) {
	t.Helper()

	cmd, _, cancel := integrationCommandWithTimeout(t, dockerCommandTimeout, "docker", "rm", "--force", container)
	defer cancel()
	if output, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(output), "No such container") {
		t.Logf("remove exact Docker fixture container %s: %v", container, err)
	}
}

func removeDockerArtifactImage(t *testing.T, image string) {
	t.Helper()

	cmd, _, cancel := integrationCommandWithTimeout(t, dockerCommandTimeout, "docker", "image", "rm", "--force", image)
	defer cancel()
	if output, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(output), "No such image") {
		t.Logf("remove exact Docker test image %s: %v", image, err)
	}
}

const dockerHealthFixtureBuilderImage = "golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb"

const dockerHealthFixtureSource = `package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	port := flag.Int("port", 8080, "listen port")
	status := flag.Int("status", http.StatusOK, "ready status")
	useTLS := flag.Bool("tls", false, "serve TLS")
	ready := flag.String("ready", "/tmp/fixture-ready", "readiness marker")
	idle := flag.Bool("idle", false, "stay alive without a listener")
	flag.Parse()

	if *idle {
		must(os.WriteFile(*ready, []byte("ready\n"), 0o600))
		for {
			time.Sleep(time.Hour)
		}
	}
	if *port <= 1024 || *port > 65535 {
		panic("fixture port must be between 1025 and 65535")
	}

	portText := strconv.Itoa(*port)
	ipv4Listener, err := net.Listen("tcp", "127.0.0.1:"+portText)
	must(err)
	listeners := []net.Listener{ipv4Listener}
	if ipv6Listener, ipv6Err := net.Listen("tcp", "[::1]:"+portText); ipv6Err == nil {
		listeners = append(listeners, ipv6Listener)
	}
	if *useTLS {
		fixtureCertificate := certificate()
		for index, listener := range listeners {
			listeners[index] = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{fixtureCertificate}})
		}
	}
	must(os.WriteFile(*ready, []byte("ready\n"), 0o600))
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(*status)
		_, _ = writer.Write([]byte("ready\n"))
	})}
	for _, listener := range listeners[1:] {
		go func() { must(server.Serve(listener)) }()
	}
	must(server.Serve(listeners[0]))
}

func certificate() tls.Certificate {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	must(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

func must(err error) {
	if err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
`
