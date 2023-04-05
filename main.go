package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	FullName string `json:"fullname"`
	Email    string `json:"email"`
	Password string `json:"password"`
	//Class    []*Class `gorm:"many2many:user_class;"`
}

type Class struct {
	gorm.Model
	Name       string `json:"name"`
	Level      string `json:"level"`
	Instructor string `json:"instructor"`
	//User       []*User `gorm:"many2many:class_user;"`
}

type Enrollment struct {
	gorm.Model
	UserID  int   `json:"user_id"`
	User    User  `gorm:"foreignKey:UserID" json:"user"`
	ClassID int   `json:"class_id"`
	Class   Class `gorm:"foreignKey:ClassID" json:"class"`
}

func main() {
	dsn := "host=containers-us-west-31.railway.app user=postgres password=iyAOHU97Nv1OPQnaWWma dbname=railway port=6996 sslmode=disable TimeZone=Asia/Jakarta"
	DB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Database Not Conection", err)
	}

	DB.AutoMigrate(&User{}, &Class{}, &Enrollment{})
	app := fiber.New()

	authMiddleware := func(c *fiber.Ctx) error {
		tokenRequest := c.Get("Authorization")
		if tokenRequest == "" || !strings.HasPrefix(tokenRequest, "Bearer ") {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "",
				"data":    nil,
			})
		}

		token, err := jwt.Parse(strings.Split(tokenRequest, " ")[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method : %v", token.Header["alg"])
			}
			return []byte("JWT_SECRET"), nil
		})

		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"message": "",
				"data":    nil,
			})
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Locals("user_id", claims["user_id"])
		} else {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"message": "",
				"data":    nil,
			})
		}

		return c.Next()
	}

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello World")
	})

	/*--------------------------Login and Register-----------------------------------*/
	app.Post("/register", func(c *fiber.Ctx) error {
		register := User{}
		if err = c.BodyParser(&register); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		if result := DB.Where("email = ?", register.Email).First(&register); result.RowsAffected != 0 {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"message": "Email not already registered",
			})
		}

		DB.Create(&register)
		return c.JSON(fiber.Map{
			"success": true,
			"message": "",
			"data":    register,
		})

	})

	app.Get("/login", func(c *fiber.Ctx) error {
		loginRequest := User{}
		if err = c.BodyParser(&loginRequest); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		login := User{}
		if result := DB.Where("email = ?", loginRequest.Email).First(&login); result.RowsAffected == 0 {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"message": "Email not Found",
			})
		}

		if loginRequest.Password != login.Password {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"message": "Password not Invalid",
			})
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": login.ID,
		})

		tokenString, err := token.SignedString([]byte("JWT_SECRET"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Login Success",
			"data":    tokenString,
		})
	})

	/*--------------------------Class Management----------------------------------*/
	app.Post("/class", func(c *fiber.Ctx) error {
		class := Class{}
		if err = c.BodyParser(&class); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		DB.Create(&class)
		return c.JSON(fiber.Map{
			"success": true,
			"message": "",
			"data":    class,
		})
	})

	app.Get("/class", func(c *fiber.Ctx) error {
		class := []Class{}

		if result := DB.Find(&class); result.RowsAffected != 0 {
			return c.JSON(fiber.Map{
				"success": true,
				"message": "",
				"data":    class,
			})
		}
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
			"data":    nil,
		})
	})

	app.Get("/class/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		class := Class{}
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		if result := DB.First(&class, id); result.RowsAffected != 0 {
			return c.JSON(fiber.Map{
				"success": true,
				"message": "",
				"data":    class,
			})
		}

		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": fmt.Sprintf("class with ID %d not found", id),
			"data":    nil,
		})
	})

	app.Put("/class/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		classRequest := Class{}
		if err = c.BodyParser(&classRequest); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		class := Class{}
		if err := DB.First(&class, id).Error; err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		classRequest.ID = uint(id)
		if classRequest.Name == "" {
			classRequest.Name = class.Name
		}

		if classRequest.Level == "" {
			classRequest.Level = class.Level
		}

		if classRequest.Instructor == "" {
			classRequest.Instructor = class.Instructor
		}

		if err := DB.Updates(&classRequest).Error; err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "",
			"data":    classRequest,
		})
	})

	app.Delete("/class/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		class := Class{}
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		if result := DB.Delete(&class, id); result.RowsAffected != 0 {
			return c.JSON(fiber.Map{
				"success": true,
				"message": fmt.Sprintf("class with ID %d  successfully deleted ", id),
				"data":    class,
			})
		}

		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "Class not found",
			"data":    nil,
		})

	})

	/*---------------------------------Enroll------------------------------------------*/
	app.Post("/enroll/:id", authMiddleware, func(c *fiber.Ctx) error {
		enrol := Enrollment{}
		id, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		class := Class{}
		err = DB.First(&class, id).Error
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		userID := int(c.Locals("user_id").(float64))
		err = DB.Where("user_id = ? AND class_id = ?", userID, id).First(&enrol).Error
		if err == nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "User has already enrolled in this class",
				"data":    nil,
			})
		}

		enrol.UserID = userID
		enrol.ClassID = id
		err = DB.Create(&enrol).Error
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"success": true,
		})

	})

	app.Get("/enroll", func(c *fiber.Ctx) error {
		enroll := []Enrollment{}

		DB.Preload("User").Preload("Class").Find(&enroll)
		return c.JSON(fiber.Map{
			"data": enroll,
		})
	})

	app.Delete("/enroll/:id", authMiddleware, func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		enroll := Enrollment{}
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		if result := DB.Delete(&enroll, id); result.RowsAffected != 0 {
			return c.Status(http.StatusOK).JSON(fiber.Map{
				"success": true,
				"message": "",
				"data":    enroll,
			})
		}

		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "Class not found",
			"data":    nil,
		})
	})

	/*---------------------------------myclass------------------------------------------*/
	app.Get("/myclass", authMiddleware, func(c *fiber.Ctx) error {
		userID := int(c.Locals("user_id").(float64))
		enrol := []Enrollment{}

		err := DB.Where("user_id = ?", userID).Find(&enrol).Error
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		classes := []Class{}
		for _, enrolment := range enrol {
			class := Class{}
			err := DB.Find(&class, enrolment.ClassID).Error
			if err != nil {
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{
					"success": false,
					"message": err.Error(),
					"data":    nil,
				})
			}
			classes = append(classes, class)
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "",
			"data":    classes,
		})
	})

	app.Delete("/myclass/:id", authMiddleware, func(c *fiber.Ctx) error {
		userID := int(c.Locals("user_id").(float64))
		classID, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		enroll := Enrollment{}
		err = DB.Where("user_id = ? AND class_id = ?", userID, classID).First(&enroll).Error
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Enrolment not found",
				"data":    nil,
			})
		}

		err = DB.Delete(&enroll).Error
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
				"data":    nil,
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "",
			"data":    nil,
		})
	})

	app.Listen(":8080")
}
