package main

import (
	"fmt"
	"io"
	"os"

	log "github.com/paullesiak/policyparser/internal/logger"
	"github.com/spf13/viper"

	"github.com/paullesiak/policyparser/pkg/parser"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}

func run() error {
	log.SetLevel(log.DebugLevel)
	configureDefaults()

	if err := readConfig(); err != nil {
		return err
	}

	log.Debugf(
		"Parsing %s file for %s cloud",
		viper.GetString("policyFile"),
		viper.GetString("cloud"))

	policyText, err := readPolicyText(viper.GetString("policyFile"))
	if err != nil {
		return err
	}
	log.Debugf("%s", policyText)

	p, err := parser.NewParser(viper.GetString("cloud"), string(policyText), viper.GetBool("urlEscaped"))
	if err != nil {
		return err
	}

	if err := p.Parse(); err != nil {
		return err
	}

	policies, err := p.GetPolicy()
	if err != nil {
		return err
	}

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	jsonData, err := p.Json()
	if err != nil {
		return err
	}
	log.Debugf("Json: \n%s", string(jsonData))

	if err := p.WriteJson(viper.GetString("outputFile")); err != nil {
		return err
	}

	log.Debugf("Written to file: %s", viper.GetString("outputFile"))
	return nil
}

func configureDefaults() {
	viper.SetDefault("cloud", "aws")
	viper.SetDefault("policyFile", "awspolicy.json")
	viper.SetDefault("urlEscaped", true)
	viper.SetDefault("outputFile", "parsed.json")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

func readConfig() error {
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	return nil
}

func readPolicyText(filename string) (_ []byte, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open policy file %q: %w", filename, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close policy file %q: %w", filename, closeErr)
		}
	}()

	policyText, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", filename, err)
	}
	return policyText, nil
}
