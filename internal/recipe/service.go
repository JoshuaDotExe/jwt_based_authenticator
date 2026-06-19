package recipe

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

type dynamoService struct {
	ddb         *dynamodb.Client
	recipeTable string
}

type recipeRecord struct {
	ID           string       `dynamodbav:"id"`
	OwnerID      string       `dynamodbav:"owner_id"`
	Title        string       `dynamodbav:"title"`
	Tags         []string     `dynamodbav:"tags"`
	Ingredients  Ingredients  `dynamodbav:"ingredients"`
	Instructions Instructions `dynamodbav:"instructions"`
	CreatedAt    string       `dynamodbav:"created_at"`
	UpdatedAt    string       `dynamodbav:"updated_at"`
}

func NewDynamoService(ddb *dynamodb.Client, recipeTable string) Service {
	return &dynamoService{
		ddb:         ddb,
		recipeTable: recipeTable,
	}
}

func (s *dynamoService) GetByOwnerID(ctx context.Context, input GetRecipesByOwnerIDRequest) ([]Recipe, error) {
	ownerID := strings.TrimSpace(input.OwnerID)
	if ownerID == "" {
		return nil, ErrInvalidRecipeInput
	}

	resp, err := s.ddb.Scan(ctx, &dynamodb.ScanInput{
		TableName:        &s.recipeTable,
		FilterExpression: awsString("owner_id = :owner_id"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":owner_id": &ddbt.AttributeValueMemberS{Value: ownerID},
		},
	})
	if err != nil {
		return nil, err
	}

	var recipeRecords []recipeRecord
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &recipeRecords)
	if err != nil {
		return nil, err
	}

	var recipes []Recipe
	for _, record := range recipeRecords {
		recipes = append(recipes, recordToRecipe(record))
	}
	return recipes, nil
}

func (s *dynamoService) Create(ctx context.Context, ownerID string, input CreateRecipeRequest) (Recipe, error) {
	ownerID = strings.TrimSpace(ownerID)
	title := strings.TrimSpace(input.Title)
	if ownerID == "" || title == "" {
		return Recipe{}, ErrInvalidRecipeInput
	}

	now := time.Now().UTC().Format(time.RFC3339)
	newRecipe := recipeRecord{
		ID:           uuid.NewString(),
		OwnerID:      ownerID,
		Title:        title,
		Tags:         normalizeTags(input.Tags),
		Ingredients:  input.Ingredients,
		Instructions: input.Instructions,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	recipeItem, err := attributevalue.MarshalMap(newRecipe)
	if err != nil {
		return Recipe{}, err
	}

	_, err = s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.recipeTable,
		Item:      recipeItem,
	})
	if err != nil {
		return Recipe{}, err
	}

	return recordToRecipe(newRecipe), nil
}

func (s *dynamoService) GetByID(ctx context.Context, recipeID string) (Recipe, error) {
	resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
	})
	if err != nil {
		return Recipe{}, err
	}

	if resp.Item == nil {
		return Recipe{}, ErrRecipeNotFound
	}

	var recipeRecord recipeRecord
	err = attributevalue.UnmarshalMap(resp.Item, &recipeRecord)
	if err != nil {
		return Recipe{}, err
	}

	return recordToRecipe(recipeRecord), nil
}

func (s *dynamoService) Update(ctx context.Context, recipeID string, input UpdateRecipeRequest) (Recipe, error) {
	recipeID = strings.TrimSpace(recipeID)
	title := strings.TrimSpace(input.Title)
	if recipeID == "" || title == "" {
		return Recipe{}, ErrInvalidRecipeInput
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ingredientsAV, err := attributevalue.Marshal(input.Ingredients)
	if err != nil {
		return Recipe{}, err
	}

	instructionsAV, err := attributevalue.Marshal(input.Instructions)
	if err != nil {
		return Recipe{}, err
	}

	tagsAV, err := attributevalue.Marshal(normalizeTags(input.Tags))
	if err != nil {
		return Recipe{}, err
	}

	resp, err := s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
		ConditionExpression: awsString("attribute_exists(id)"),
		UpdateExpression:    awsString("SET title = :title, tags = :tags, ingredients = :ingredients, instructions = :instructions, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":title":        &ddbt.AttributeValueMemberS{Value: title},
			":tags":         tagsAV,
			":ingredients":  ingredientsAV,
			":instructions": instructionsAV,
			":updated_at":   &ddbt.AttributeValueMemberS{Value: now},
		},
		ReturnValues: ddbt.ReturnValueAllNew,
	})
	if err != nil {
		var condErr *ddbt.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return Recipe{}, ErrRecipeNotFound
		}
		return Recipe{}, err
	}

	var updated recipeRecord
	if err := attributevalue.UnmarshalMap(resp.Attributes, &updated); err != nil {
		return Recipe{}, err
	}

	return recordToRecipe(updated), nil
}

func (s *dynamoService) Delete(ctx context.Context, recipeID string) error {
	recipeID = strings.TrimSpace(recipeID)
	if recipeID == "" {
		return ErrInvalidRecipeInput
	}

	_, err := s.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
		ConditionExpression: awsString("attribute_exists(id)"),
	})
	if err != nil {
		var condErr *ddbt.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrRecipeNotFound
		}
		return err
	}

	return nil
}

func awsString(value string) *string {
	return &value
}

func recordToRecipe(record recipeRecord) Recipe {
	return Recipe{
		ID:           record.ID,
		OwnerID:      record.OwnerID,
		Title:        record.Title,
		Tags:         append([]string(nil), record.Tags...),
		Ingredients:  record.Ingredients,
		Instructions: record.Instructions,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
	}
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return []string{}
	}

	normalized := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		clean := strings.TrimSpace(tag)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		normalized = append(normalized, clean)
	}

	return normalized
}
