package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	Version        = "0.3.1"
	SevenZipURL    = "https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.exe"
	SevenZipSHA256 = "9b697f65ecc2d9b0152f5ee96d72dde522a7827690349d9307935dacf40f42ec"
)

var SuCatalogURLs = []string{
	"https://swscan.apple.com/content/catalogs/others/index-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
	"https://swscan.apple.com/content/catalogs/others/index-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
	"https://swscan.apple.com/content/catalogs/others/index-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
	"https://swscan.apple.com/content/catalogs/others/index-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
}

type Options struct {
	Models      multiFlag
	Install     bool
	OutputDir   string
	KeepFiles   bool
	ProductID   string
	ShowVersion bool
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func status(msg string) {
	fmt.Printf("%s\n", msg)
}

func getCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func getMachineModel() (string, error) {
	if runtime.GOOS == "windows" {
		out, err := getCommandOutput("wmic", "computersystem", "get", "model", "/format:VALUE")
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Model=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Model=")), nil
			}
		}
		return "Unknown", nil
	} else if runtime.GOOS == "darwin" {
		out, err := getCommandOutput("system_profiler", "SPHardwareDataType")
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Model Identifier:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
		}
		return "MacBookAir6,2", nil
	}
	return "Unknown", fmt.Errorf("unsupported platform for auto-detecting model")
}

func isValidMacModel(model string) bool {
	matched, _ := regexp.MatchString(`^(MacBook\d+,\d+|MacBookAir\d+,\d+|MacBookPro\d+,\d+|iMac\d+,\d+|Macmini\d+,\d+|MacPro\d+,\d+|MacStudio\d+,\d+|Mac\d+,\d+)$`, model)
	return matched
}

type WriteCounter struct {
	Total      uint64
	Downloaded uint64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Downloaded += uint64(n)
	wc.printProgress()
	return n, nil
}

func (wc *WriteCounter) printProgress() {
	if wc.Total > 0 {
		percent := float64(wc.Downloaded) * 100.0 / float64(wc.Total)
		fmt.Fprintf(os.Stderr, "\r\033[K%5.1f%% %d / %d bytes", percent, wc.Downloaded, wc.Total)
	} else {
		fmt.Fprintf(os.Stderr, "\r\033[Kread %d bytes", wc.Downloaded)
	}
}

func downloadCatalog() ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for _, url := range SuCatalogURLs {
		status(fmt.Sprintf("Attempting to fetch catalog from: %s", url))
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "SoftwareUpdate/1.0 (Macintosh; Intel Mac OS X 10_15_7)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				return data, nil
			}
		} else {
			resp.Body.Close()
		}
	}

	return nil, fmt.Errorf("failed to download sucatalog from all available Apple endpoints")
}

func downloadFile(url string, filepathStr string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SoftwareUpdate/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepathStr)
	if err != nil {
		return err
	}
	defer out.Close()

	counter := &WriteCounter{Total: uint64(resp.ContentLength)}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	fmt.Fprint(os.Stderr, "\n")
	return err
}

func verifyFileSHA256(filepathStr string, expectedHash string) error {
	file, err := os.Open(filepathStr)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("SHA-256 mismatch!\nExpected: %s\nGot:      %s", expectedHash, actualHash)
	}

	return nil
}

func sevenzipExtract(arcfile string, command string, outDir string) error {
	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	sevenZipPath := filepath.Join(systemDrive+"\\", "Program Files", "7-Zip", "7z.exe")

	if outDir == "" {
		outDir = filepath.Dir(arcfile)
	}

	args := []string{command, "-o" + outDir, "-y", arcfile}
	status(fmt.Sprintf("Calling 7-Zip command: %s %s", sevenZipPath, strings.Join(args, " ")))

	cmd := exec.Command(sevenZipPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func postInstallConfig() {
	regdata := `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Apple Inc.\Apple Keyboard Support]
"FirstTimeRun"=dword:00000000`

	tmpFile, err := os.CreateTemp("", "*.reg")
	if err != nil {
		return
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString(regdata)
	tmpFile.Close()

	exec.Command("regedit.exe", "/s", tmpFile.Name()).Run()
}

type matchFound struct{ path string }
func (e matchFound) Error() string { return e.path }

func findBootcampMSI(searchDir string) string {
	candidates := []string{"BootCamp64.msi", "BootCamp.msi"}
	var foundPath string
	
	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		for _, msi := range candidates {
			if info.Name() == msi {
				foundPath = path
				return matchFound{path: path}
			}
		}
		return nil
	})
	
	if err != nil {
		if mf, ok := err.(matchFound); ok {
			return mf.path
		}
	}
	return foundPath
}

func installBootcamp(msiPath string) {
	logPath := filepath.Join(os.TempDir(), "BootCamp_Install.log")
	cmd := exec.Command("msiexec", "/i", msiPath, "/qb-", "/norestart", "/log", logPath)
	status(fmt.Sprintf("Executing command: %s", strings.Join(cmd.Args, " ")))
	cmd.Run()

	status("Install log output:")
	if data, err := os.ReadFile(logPath); err == nil {
		fmt.Println(string(data))
	}
	postInstallConfig()
}

func main() {
	var opts Options
	flag.Var(&opts.Models, "m", "System model identifier to use")
	flag.Var(&opts.Models, "model", "System model identifier to use")
	flag.BoolVar(&opts.Install, "i", false, "Perform install automatically (Windows only)")
	flag.BoolVar(&opts.Install, "install", false, "Perform install automatically (Windows only)")
	flag.StringVar(&opts.OutputDir, "o", "", "Base output path")
	flag.StringVar(&opts.OutputDir, "output-dir", "", "Base output path")
	flag.BoolVar(&opts.KeepFiles, "k", false, "Keep downloaded/extracted files")
	flag.BoolVar(&opts.KeepFiles, "keep-files", false, "Keep downloaded/extracted files")
	flag.StringVar(&opts.ProductID, "p", "", "Specify an exact product ID")
	flag.StringVar(&opts.ProductID, "product-id", "", "Specify an exact product ID")
	flag.BoolVar(&opts.ShowVersion, "V", false, "Output version")
	flag.BoolVar(&opts.ShowVersion, "version", false, "Output version")

	flag.Parse()

	if opts.ShowVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	if opts.Install {
		if runtime.GOOS == "darwin" {
			log.Fatal("Installing Boot Camp can only be done on Windows!")
		}
		if runtime.GOOS == "windows" && runtime.GOARCH != "amd64" {
			log.Fatal("Installing on anything other than 64-bit Windows is currently not supported!")
		}
	}

	outputDir := opts.OutputDir
	if outputDir == "" {
		var err error
		outputDir, err = os.Getwd()
		if err != nil {
			outputDir = "."
		}
		if strings.Contains(strings.ToLower(outputDir), "system32") {
			systemDrive := os.Getenv("SYSTEMDRIVE")
			if systemDrive == "" {
				systemDrive = "C:"
			}
			outputDir = systemDrive + "\\"
			status(fmt.Sprintf("Changing output directory to %s to work around system32 issue.", outputDir))
		}
	} else {
		info, err := os.Stat(outputDir)
		if err != nil || !info.IsDir() {
			log.Fatalf("Output directory %s specified doesn't exist!", outputDir)
		}
	}

	if opts.KeepFiles && !opts.Install {
		log.Fatal("The --keep-files option is only useful when used with --install option!")
	}

	var models []string
	if len(opts.Models) > 0 {
		if opts.Install {
			status("Ignoring '--model' when '--install' is used.")
		}
		models = opts.Models
	} else {
		m, err := getMachineModel()
		if err != nil {
			log.Fatalf("Failed to detect machine model: %v", err)
		}
		models = []string{m}
	}

	for _, m := range models {
		if !isValidMacModel(m) {
			log.Fatalf("Error: '%s' is not a valid Mac model identifier.", m)
		}
	}

	status(fmt.Sprintf("Using Mac model(s): %s.", strings.Join(models, ", ")))

	catalogData, err := downloadCatalog()
	if err != nil {
		log.Fatalf("Error downloading catalog: %v", err)
	}

	status(fmt.Sprintf("Successfully fetched Apple catalog (%d bytes).", len(catalogData)))
}
```[cite: 2]
