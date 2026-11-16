package output

import (
	"encoding/json"
	"io"

	"github.com/n0rm4l-me/meshscan/internal/model"
)

const (
	sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName    = "meshscan"
	toolURI     = "https://github.com/n0rm4l-me/meshscan"
)

// Rule describes one check for the SARIF rule catalog.
type Rule struct {
	ID          string
	Description string
	Severity    model.Severity
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	ShortDescription     sarifText   `json:"shortDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// SARIF writes findings as a SARIF 2.1.0 log for generic SARIF consumers.
//
// Findings describe live cluster resources, not source files, so results carry
// logical locations ("namespace/Kind/name") and no physical locations. Some
// SARIF consumers, GitHub code scanning among them, may require file locations
// and reject such a log.
func SARIF(w io.Writer, findings []model.Finding, rules []Rule, toolVersion string) error {
	catalog := make([]sarifRule, 0, len(rules))
	index := map[string]int{}
	addRule := func(r Rule) int {
		index[r.ID] = len(catalog)
		catalog = append(catalog, sarifRule{
			ID:                   r.ID,
			ShortDescription:     sarifText{Text: r.Description},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(r.Severity)},
		})
		return index[r.ID]
	}
	for _, r := range rules {
		addRule(r)
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		idx, ok := index[f.Check]
		if !ok {
			// A finding from a check missing in the catalog still needs a rule entry.
			idx = addRule(Rule{ID: f.Check, Description: f.Check, Severity: f.Severity})
		}
		props := map[string]string{"severity": f.Severity.String(), "namespace": f.Namespace}
		if f.Fix != "" {
			props["fix"] = f.Fix
		}
		results = append(results, sarifResult{
			RuleID:    f.Check,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{{LogicalLocations: []sarifLogicalLocation{{
				Name:               f.Resource,
				FullyQualifiedName: f.Namespace + "/" + f.Resource,
				Kind:               "resource",
			}}}},
			Properties: props,
		})
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        toolVersion,
				InformationURI: toolURI,
				Rules:          catalog,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// sarifLevel maps meshscan severities to SARIF result levels.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	}
	return "note"
}
