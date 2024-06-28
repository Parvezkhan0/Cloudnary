package utils

import (
	"context"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// my vpc id : vpc-046494ac9a93c4532

// ConnectToDB establishes a connection to the MongoDB database
func ConnectToDB(ctx context.Context) (*mongo.Client, error) {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	// Retrieve MongoDB URI from environment variable
	uri := os.Getenv("DB_URI")
	if uri == "" {
		return nil, fmt.Errorf("DB_URI environment variable not set")
	}

	// Use the provided URI to connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("error connecting to MongoDB: %w", err)
	}

	// Ping the database to verify connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error pinging MongoDB: %w", err)
	}

	// Create indexes for the 'users' collection
	err = createCollectionIndexes(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("error creating collection indexes: %w", err)
	}

	fmt.Println("Connected to MongoDB successfully!")
	return client, nil
}

// createCollectionIndexes creates indexes for the 'users' collection
func createCollectionIndexes(ctx context.Context, client *mongo.Client) error {
	// Retrieve database name and collection name from environment variables
	dbName := os.Getenv("DB_DATABASE")
	userCollection := os.Getenv("DB_USER_COLLECTION")

	collection := client.Database(dbName).Collection(userCollection)

	// Create index on username for uniqueness
	_, err := collection.Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys:    bson.M{"username": 1},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		return err
	}

	// Create index on email for uniqueness
	_, err = collection.Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys:    bson.M{"email": 1},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		return err
	}

	return nil
}
