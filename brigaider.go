package main

import (
	"crypto/tls"
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
	"sort"
	"strings"
	"time"
)

const (
	Version      = "0.2.6"
	SuCatalogURL = "https://swscan.apple.com/content/catalogs/others/index-11-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog"
	SevenZipURL  = "https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.exe"
)

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
	fmt.Printf("%s\n\n", msg)
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
			return "MacBookAir6,2", err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Model=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Model=")), nil
			}
		}
		return "MacBookAir6,2", nil
	} else if runtime.GOOS == "darwin" {
		out, err := getCommandOutput("system_profiler", "SPHardwareDataType")
		if err != nil {
			return "MacBookAir6,2", err
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
	return "MacBookAir6,2", fmt.Errorf("unsupported platform for auto-detecting model")
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
		fmt.Fprintf(os.Stderr, "\r%5.1f%% %d / %d bytes", percent, wc.Downloaded, wc.Total)
		if wc.Downloaded >= wc.Total {
			fmt.Fprint(os.Stderr, "\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "\rread %d bytes", wc.Downloaded)
	}
}

func downloadFile(url string, filepathStr string, useClient bool) error {
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
	return err
}

func sevenzipExtract(arcfile string, command string, outDir string) {
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
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Command failure: %s exited with error: %v", strings.Join(append([]string{sevenZipPath}, args...), " "), err)
	}
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

func fetchURLContent(url string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SoftwareUpdate/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func main() {
	scriptDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))

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

	var outputDir string
	if opts.OutputDir != "" {
		info, err := os.Stat(opts.OutputDir)
		if err != nil || !info.IsDir() {
			log.Fatalf("Output directory %s that was specified doesn't exist!", opts.OutputDir)
		}
		outputDir = opts.OutputDir
	} else {
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
			status(fmt.Sprintf("Changing output directory to %s to work around an issue when running the installer out of 'system32'.", outputDir))
		}
	}

	if opts.KeepFiles && !opts.Install {
		log.Fatal("The --keep-files option is only useful when used with --install option!")
	}

	var models []string
	if len(opts.Models) > 0 {
		if opts.Install {
			status("Ignoring '--model' when '--install' is used. The Boot Camp installer won't allow other models to be installed, anyway.")
		}
		models = opts.Models
	} else {
		m, err := getMachineModel()
		if err != nil {
			log.Fatalf("Failed to detect machine model: %v", err)
		}
		models = []string{m}
	}

	if len(models) > 1 {
		status(fmt.Sprintf("Using Mac models: %s.", strings.Join(models, ", ")))
	} else {
		status(fmt.Sprintf("Using Mac model: %s.", strings.Join(models, ", ")))
	}

	for _, model := range models {
		sucatalogURL := SuCatalogURL
		_ = filepath.Join(scriptDir, "brigadier.plist")

		status(fmt.Sprintf("Fetching catalog from %s", sucatalogURL))
		catalogData, err := fetchURLContent(sucatalogURL)
		if err != nil {
			log.Fatalf("Failed to fetch catalog: %v", err)
		}

		catalogStr := string(catalogData)
		reModel := regexp.MustCompile(`([a-zA-Z]{4,12}[1-9]{1,2}\,[1-6])`)
		
		status(fmt.Sprintf("Searching catalog for BootCamp packages matching model %s...", model))
		
		distURLRegex := regexp.MustCompile(`<key>Distributions</key>\s*<dict>[\s\S]*?<key>English</key>\s*<string>(https://[^<]+)</string>`)
		pkgURLRegex := regexp.MustCompile(`<key>Packages</key>\s*<array>\s*<dict>[\s\S]*?<key>URL</key>\s*<string>(https://[^<]+\.pkg)</string>`)
		postDateRegex := regexp.MustCompile(`<key>PostDate</key>\s*<date>([^<]+)</date>`)

		type ProdInfo struct {
			ProductID string
			DistURL   string
			PkgURL    string
			PostDate  string
		}

		var matchedProds []ProdInfo
		prodBlocks := strings.Split(catalogStr, "<key>")

		for _, block := range prodBlocks {
			if !strings.Contains(block, "ServerMetadataURL") || !strings.Contains(block, "BootCamp") {
				continue
			}
			distMatch := distURLRegex.FindStringSubmatch(block)
			pkgMatch := pkgURLRegex.FindStringSubmatch(block)
			dateMatch := postDateRegex.FindStringSubmatch(block)

			if len(distMatch) > 1 && len(pkgMatch) > 1 {
				lines := strings.Split(block, "</key>")
				var prodID = "Unknown"
				if len(lines) > 0 {
					prodID = strings.TrimSpace(strings.ReplaceAll(lines[0], "<key>", ""))
				}

				dURL := distMatch[1]
				pURL := pkgMatch[1]
				pDate := ""
				if len(dateMatch) > 1 {
					pDate = dateMatch[1]
				}

				distData, err := fetchURLContent(dURL)
				if err == nil {
					distStr := string(distData)
					if strings.Contains(distStr, model) || reModel.MatchString(distStr) {
						matchedModels := reModel.FindAllString(distStr, -1)
						status(fmt.Sprintf("Model supported in package distribution file at %s.", dURL))
						status(fmt.Sprintf("Distribution supports models: %s.", strings.Join(matchedModels, ", ")))
						matchedProds = append(matchedProds, ProdInfo{
							ProductID: prodID,
							DistURL:   dURL,
							PkgURL:    pURL,
							PostDate:  pDate,
						})
					}
				}
			}
		}

		if len(matchedProds) == 0 {
			log.Fatalf("Couldn't find a Boot Camp ESD for the model %s in the given software update catalog.", model)
		}

		var chosenPkg ProdInfo
		if len(matchedProds) == 1 {
			chosenPkg = matchedProds[0]
			if opts.ProductID != "" {
				log.Fatal("--product-id option is only applicable when multiple ESDs are found for a model.")
			}
		} else {
			fmt.Println("There is more than one ESD product available for this model:")
			type RatedProd struct {
				info ProdInfo
				t    time.Time
			}
			var rated []RatedProd
			for _, p := range matchedProds {
				t, _ := time.Parse(time.RFC3339, p.PostDate)
				fmt.Printf("%s: PostDate %s\n", p.ProductID, p.PostDate)
				rated = append(rated, RatedProd{info: p, t: t})
			}

			sort.Slice(rated, func(i, j int) bool {
				return rated[i].t.After(rated[j].t)
			})

			chosenPkg = rated[0].info
			if opts.ProductID != "" {
				found := false
				for _, p := range matchedProds {
					if p.ProductID == opts.ProductID {
						chosenPkg = p
						found = true
						break
					}
				}
				if !found {
					log.Fatalf("Product specified with '--product-id %s' either doesn't exist or was not found applicable", opts.ProductID)
				}
				fmt.Printf("Selecting manually-chosen product %s.\n", chosenPkg.ProductID)
			} else {
				fmt.Printf("Selecting %s as it's the most recently posted.\n", chosenPkg.ProductID)
			}
		}

		landingDir := filepath.Join(outputDir, "BootCamp-"+chosenPkg.ProductID)
		if _, err := os.Stat(landingDir); err == nil {
			status(fmt.Sprintf("Final output path %s already exists, removing it...", landingDir))
			os.RemoveAll(landingDir)
		}

		status(fmt.Sprintf("Making directory %s..", landingDir))
		os.MkdirAll(landingDir, 0755)

		arcWorkdir, _ := os.MkdirTemp("", "bootcamp-unpack_*")
		defer os.RemoveAll(arcWorkdir)

		pkgFileName := filepath.Base(chosenPkg.PkgURL)
		pkgDlPath := filepath.Join(arcWorkdir, pkgFileName)

		status(fmt.Sprintf("Fetching Boot Camp product at URL %s.", chosenPkg.PkgURL))
		downloadFile(chosenPkg.PkgURL, pkgDlPath, false)

		if runtime.GOOS == "windows" {
			weInstalled7zip := false
			sevenZipBinary := filepath.Join(os.Getenv("SYSTEMDRIVE")+"\\", "Program Files", "7-Zip", "7z.exe")
			if _, err := os.Stat(sevenZipBinary); os.IsNotExist(err) {
				tempDir, _ := os.MkdirTemp("", "7zip_*")
				defer os.RemoveAll(tempDir)
				sevenzipExeDlPath := filepath.Join(tempDir, filepath.Base(SevenZipURL))
				status("Downloading 7-zip...")
				downloadFile(SevenZipURL, sevenzipExeDlPath, true)
				status("We need to install 7-Zip..")
				exec.Command(sevenzipExeDlPath, "/S").Run()
				weInstalled7zip = true
			}

			status("Extracting...")
			for _, arcName := range []string{pkgDlPath, filepath.Join(arcWorkdir, "Payload"), filepath.Join(arcWorkdir, "Payload~")} {
				if _, err := os.Stat(arcName); err == nil {
					sevenzipExtract(arcName, "e", arcWorkdir)
				}
			}

			dmgPath := filepath.Join(arcWorkdir, "WindowsSupport.dmg")
			if _, err := os.Stat(dmgPath); err == nil {
				sevenzipExtract(dmgPath, "x", landingDir)
			}

			if weInstalled7zip {
				status("Cleaning up 7-Zip install...")
			}

			if opts.Install {
				status("Installing Boot Camp...")
				msiPath := findBootcampMSI(landingDir)
				if msiPath != "" {
					installBootcamp(msiPath)
				}
				if !opts.KeepFiles {
					os.RemoveAll(landingDir)
				}
			}
		} else if runtime.GOOS == "darwin" {
			status("Expanding flat package...")
			exec.Command("/usr/sbin/pkgutil", "--expand", pkgDlPath, filepath.Join(arcWorkdir, "pkg")).Run()
			status("Extracting Payload...")
			exec.Command("/usr/bin/tar", "-xz", "-C", arcWorkdir, "-f", filepath.Join(arcWorkdir, "pkg", "Payload")).Run()
			outputFile := filepath.Join(landingDir, "WindowsSupport.dmg")
			srcDmg := filepath.Join(arcWorkdir, "Library/Application Support/BootCamp/WindowsSupport.dmg")
			os.Rename(srcDmg, outputFile)
			status(fmt.Sprintf("Extracted to %s.", outputFile))
		} else if runtime.GOOS == "linux" {
			status("Extracting for Linux...")
			for _, arcName := range []string{pkgDlPath, filepath.Join(arcWorkdir, "Payload"), filepath.Join(arcWorkdir, "Payload~")} {
				if _, err := os.Stat(arcName); err == nil {
					exec.Command("7z", "x", arcName, "-o"+arcWorkdir).Run()
				}
			}
			srcDmg := filepath.Join(arcWorkdir, "Library/Application Support/BootCamp/WindowsSupport.dmg")
			outputFile := filepath.Join(landingDir, "WindowsSupport.dmg")
			os.Rename(srcDmg, outputFile)
			exec.Command("7z", "-o"+landingDir, "x", outputFile).Run()
			status(fmt.Sprintf("Extracted to %s.", outputFile))
		}
	}

	status("Done.")
}
