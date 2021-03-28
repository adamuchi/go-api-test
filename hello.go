package main

import (
	"errors"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Claims struct {
	Role string `json:"role"`
	WhoAmI string `json:"whoami"`
	ExpiresAt int64 `json:"exp"`
	IssuedAt int64 `json:"iat"`
}

func (c Claims) Valid() error {
	if c.ExpiresAt <= time.Now().Unix() { return errors.New("Expired"); }
	return nil
}

func main() {
	secret := []byte(uuid.NewString())
	fmt.Println("Secret", secret)

	lifespan, err := time.ParseDuration("15m")
	if err != nil {
		panic("Did not parse 15m")
	}

	adminOnly := func(c *gin.Context) {
		auth := c.Request.Header.Get("Authorization")
		chunks := strings.Split(auth, "Bearer ")
		if len(chunks) != 2 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		bearer := chunks[1]
		token, err := jwt.ParseWithClaims(bearer, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return secret, nil
		})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !(ok && token.Valid) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if claims.ExpiresAt < time.Now().Unix() {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		fmt.Println(claims)
		c.Next()
	}
	
	r := gin.Default()

	r.Use(gin.Recovery())

	r.GET("/ping", func (c *gin.Context) {
		id := uuid.NewString()
		now := time.Now()
		body := gin.H{
			"id": id,
			"name": "Test",
			"timestamp": now.Format(time.RFC3339),
		}
		fmt.Println(body)
		c.JSON(200, body)
	})

	r.GET("/login", func (c *gin.Context) {
		now := time.Now()
		claims := Claims{
			Role: "admin",
			WhoAmI: "Adam",
			ExpiresAt: now.Add(lifespan).Unix(),
			IssuedAt: now.Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(secret)
		if err != nil {
			panic(err)
		}
		body := gin.H{"jwt": signed}
		fmt.Println(body)
		c.JSON(200, body)
	})

	r.POST("/admin", adminOnly, func (c *gin.Context) {
		c.String(200, "Welcome!")
	})

	r.Run() // 0.0.0.0:8080
}