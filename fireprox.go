package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigateway"
)

type FireProx struct {
	client *apigateway.APIGateway
	region string
	apiID  string
	url    string
}

func NewFireProx(region, apiID, url string) (*FireProx, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	client := apigateway.New(sess)
	return &FireProx{
		client: client,
		region: region,
		apiID:  apiID,
		url:    url,
	}, nil
}

func (fp *FireProx) ListAPIs() error {
	result, err := fp.client.GetRestApis(&apigateway.GetRestApisInput{})
	if err != nil {
		return err
	}

	for _, item := range result.Items {
		fmt.Printf("API ID: %s, Name: %s\n", *item.Id, *item.Name)
	}
	return nil
}

func (fp *FireProx) CreateAPI() error {
	if fp.url == "" {
		return errors.New("please provide a valid URL endpoint")
	}

	template := fp.getTemplate()
	resp, err := fp.client.ImportRestApi(&apigateway.ImportRestApiInput{
		Body: template,
		Parameters: map[string]*string{
			"endpointConfigurationTypes": aws.String("REGIONAL"),
		},
	})
	if err != nil {
		return err
	}

	_, proxyURL, err := fp.createDeployment(*resp.Id)
	if err != nil {
		return err
	}

	fmt.Printf("Created API: %s, Proxy URL: %s\n", *resp.Id, proxyURL)
	return nil
}

func (fp *FireProx) UpdateAPI() error {
	if fp.apiID == "" || fp.url == "" {
		return errors.New("please provide a valid API ID and URL endpoint")
	}

	resourceID, err := fp.getResource(fp.apiID)
	if err != nil {
		return err
	}

	_, err = fp.client.UpdateIntegration(&apigateway.UpdateIntegrationInput{
		RestApiId:  aws.String(fp.apiID),
		ResourceId: aws.String(resourceID),
		HttpMethod: aws.String("ANY"),
		PatchOperations: []*apigateway.PatchOperation{
			{
				Op:    aws.String("replace"),
				Path:  aws.String("/uri"),
				Value: aws.String(fmt.Sprintf("%s/{proxy}", fp.url)),
			},
		},
	})
	return err
}

func (fp *FireProx) DeleteAPI() error {
	if fp.apiID == "" {
		return errors.New("please provide a valid API ID")
	}

	_, err := fp.client.DeleteRestApi(&apigateway.DeleteRestApiInput{
		RestApiId: aws.String(fp.apiID),
	})
	return err
}

func (fp *FireProx) getTemplate() []byte {
	title := fmt.Sprintf("fireprox_%s", extractDomain(fp.url))
	versionDate := time.Now().Format(time.RFC3339)

	template := map[string]interface{}{
		"swagger": "2.0",
		"info": map[string]string{
			"version": versionDate,
			"title":   title,
		},
		"basePath": "/",
		"schemes":  []string{"https"},
		"paths": map[string]interface{}{
			"/{proxy+}": map[string]interface{}{
				"x-amazon-apigateway-any-method": map[string]interface{}{
					"x-amazon-apigateway-integration": map[string]interface{}{
						"uri": fmt.Sprintf("%s/{proxy}", fp.url),
						"responses": map[string]interface{}{
							"default": map[string]string{"statusCode": "200"},
						},
						"requestParameters": map[string]string{
							"integration.request.path.proxy": "method.request.path.proxy",
						},
						"passthroughBehavior": "when_no_match",
						"httpMethod":          "ANY",
						"type":                "http_proxy",
					},
				},
			},
		},
	}

	data, _ := json.Marshal(template)
	return data
}

func (fp *FireProx) createDeployment(apiID string) (string, string, error) {
	resp, err := fp.client.CreateDeployment(&apigateway.CreateDeploymentInput{
		RestApiId:        aws.String(apiID),
		StageName:        aws.String("fireprox"),
		StageDescription: aws.String("FireProx Prod"),
		Description:      aws.String("FireProx Production Deployment"),
	})
	if err != nil {
		return "", "", err
	}

	resourceID := *resp.Id
	proxyURL := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/fireprox/", apiID, fp.region)

	return resourceID, proxyURL, nil
}

func (fp *FireProx) getResource(apiID string) (string, error) {
	resp, err := fp.client.GetResources(&apigateway.GetResourcesInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return "", err
	}

	for _, item := range resp.Items {
		if *item.Path == "/{proxy+}" {
			return *item.Id, nil
		}
	}
	return "", errors.New("resource not found")
}

func extractDomain(url string) string {
	// Basic extraction logic for domain
	return url // This should include proper logic to extract the domain
}
