package main

import (
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/elazarl/goproxy"
	toml "github.com/pelletier/go-toml"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
)

type Pattern struct {
	Pattern      *regexp.Regexp
	Substitution string
}

type PerHostConfig struct {
	Name     string
	Patterns []Pattern
}

type Config map[string]*PerHostConfig

var placeholderRegexp = regexp.MustCompile("\\$(?:\\$|[0-9]+)")

func loadConfig(tomlFile string) (Config, error) {
	config, err := toml.LoadFile(tomlFile)
	if err != nil {
		return nil, fmt.Errorf("could not open %s (%s)", tomlFile, err.Error())
	}
	_hostsConfig := config.Get("host")
	if _hostsConfig == nil {
		return make(Config), nil
	}

	hostsConfig, ok := _hostsConfig.(*toml.TomlTree)
	if !ok {
		return nil, fmt.Errorf("host must contain per-host pattern definitions")
	}
	hosts := make(Config)
	for _, name := range hostsConfig.Keys() {
		_patternsConfig := hostsConfig.GetPath([]string{name})
		patternsConfig, ok := _patternsConfig.(*toml.TomlTree)
		if !ok {
			return nil, fmt.Errorf("invalid per-host pattern definition for %s", name)
		}
		patterns := make([]Pattern, 0)
		for _, pattern := range patternsConfig.Keys() {
			_substition := patternsConfig.GetPath([]string{pattern})
			substition, ok := _substition.(string)
			if !ok {
				return nil, fmt.Errorf("pattern value must be a string")
			}
			patternRegexp, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("pattern (%s) is not a valid regular expression (%s)", pattern, err.Error())
			}
			patterns = append(patterns, Pattern{patternRegexp, substition})
		}
		hosts[name] = &PerHostConfig{Name: name, Patterns: patterns}
	}
	return hosts, nil
}

func main() {
	var listenOn string
	progname := os.Args[0]
	flag.StringVar(&listenOn, "l", ":8080", "\"addr:port\" on which the server listens")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s -l [LISTEN] config\n", progname)
		flag.PrintDefaults()
		os.Exit(255)
	}
	config, err := loadConfig(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", progname, err.Error())
		os.Exit(1)
	}
	if len(config) == 0 {
		fmt.Fprintf(os.Stderr, "%s: warning: no patterns defined\n", progname)
	}
	log := logrus.New()
	proxy := goproxy.NewProxyHttpServer()
	for _, perHostConfig := range config {
		func(perHostConfig *PerHostConfig) {
			proxy.OnRequest(goproxy.DstHostIs(perHostConfig.Name)).DoFunc(
				func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					subm := []string(nil)
					substitution := ""
					for _, pattern := range perHostConfig.Patterns {
						subm = pattern.Pattern.FindStringSubmatch(r.URL.Path)
						if subm != nil {
							log.Debugf("%s matched to pattern %s", r.URL.Path, pattern.Pattern.String())
							substitution = pattern.Substitution
							break
						}
					}
					if subm != nil {
						newUrl := placeholderRegexp.ReplaceAllStringFunc(substitution, func(m string) string {
							if m[1] == '$' {
								return m
							}
							submatchIndex, err := strconv.Atoi(m[1:])
							if err != nil {
								log.Errorf("Invalid substitution string: %s", m)
								return m
							}
							if submatchIndex < 1 || submatchIndex > len(subm) {
								log.Errorf("Invalid substitution string: %s", m)
								return m
							}
							return subm[submatchIndex-1] // submatchIndex is 1-based
						})
						newRequest := &http.Request{}
						*newRequest = *r
						newRequest.URL, err = url.Parse(newUrl)
						if err != nil {
							log.Error(err)
						}
						newRequest.URL.User = r.URL.User
						r = newRequest
						log.Infof("%s %s => %s", r.Method, r.RequestURI, r.URL.String())
					} else {
						log.Infof("%s %s", r.Method, r.RequestURI)
					}
					return r, nil
				})
		}(perHostConfig)
	}
	log.Fatal(http.ListenAndServe(listenOn, proxy))
}
