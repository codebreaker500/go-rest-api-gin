package controller

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func GetUsers(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Get users"})
}