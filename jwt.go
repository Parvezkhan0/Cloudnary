package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	models "Blueora/Authentication/backend/model" // Replace with your model path
)

// Claims represents the custom claims for the JWT
type Claims struct {
	Username string `json:"username"`
	UserID   string `json:"userID"`
	jwt.StandardClaims
}

// validateUsername checks if the username meets the requirements
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if strings.ContainsRune(username, ' ') {
		return fmt.Errorf("username cannot contain spaces")
	}

	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", username)
	if !match {
		return fmt.Errorf("username can only contain alphanumeric characters")
	}

	return nil
}

// SignupHandler handles user signup requests
func SignupHandler(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate username
		err = validateUsername(user.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Hash the password before storing
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		user.Password = string(hashedPassword)

		// Check for username uniqueness in database
		err = CheckUsernameUnique(client, user.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Insert the user into the database
		collection := client.Database(os.Getenv("DB_DATABASE")).Collection(os.Getenv("DB_USER_COLLECTION"))
		_, err = collection.InsertOne(context.Background(), user)
		if err != nil {
			http.Error(w, "Failed to insert user into database", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "User created successfully")
	}
}

// LoginHandler handles user login requests and generates JWT token upon successful login
func LoginHandler(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Retrieve the user from the database
		collection := client.Database(os.Getenv("DB_DATABASE")).Collection(os.Getenv("DB_USER_COLLECTION"))
		filter := bson.M{"username": user.Username}
		var storedUser models.User
		findResult := collection.FindOne(context.Background(), filter)
		err = findResult.Decode(&storedUser)
		if err != nil {
			// Handle user not found error
			if err == mongo.ErrNoDocuments {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Failed to retrieve user from database", http.StatusInternalServerError)
			}
			return
		}

		// Compare hashed passwords
		err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Generate JWT token
		expirationTime := time.Now().Add(time.Minute * 15) // Set expiration time for 15 minutes
		claims := &Claims{
			Username: storedUser.Username,
			UserID:   storedUser.ID.Hex(), // Convert ObjectID to string
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
				Issuer:    "your_application_name", // Replace with your application name
			},
		}
		secretKey := os.Getenv("JWT_SECRET_KEY")
		if secretKey == "" {
			http.Error(w, "JWT secret key not found in environment variable. Please set JWT_SECRET_KEY", http.StatusInternalServerError)
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString([]byte(secretKey))
		if err != nil {
			http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
			return
		}

		// Respond with successful login message and JWT token
		w.WriteHeader(http.StatusOK)
		response := map[string]string{"message": "Login successful", "token": ss}
		json.NewEncoder(w).Encode(response)
	}
}

// CheckUsernameUnique checks if the username is unique in the database
func CheckUsernameUnique(client *mongo.Client, username string) error {
	collection := client.Database(os.Getenv("DB_DATABASE")).Collection(os.Getenv("DB_USER_COLLECTION"))
	filter := bson.M{"username": username}
	count, err := collection.CountDocuments(context.Background(), filter)
	if err != nil {
		return fmt.Errorf("failed to check username uniqueness: %v", err)
	}
	if count > 0 {
		return fmt.Errorf("username already exists")
	}
	return nil
}
