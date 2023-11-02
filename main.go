package main

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"

	//"github.com/gofiber/fiber/v2/middleware/requestid"

	jwtware "github.com/gofiber/jwt/v4"
	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Signup struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Command struct {
	Device string `json:"device"`
	Signal string `json:"signal"`
}

var db *sql.DB

var jwtSecret string = "logtest"

func main() {
	var err error
	db, err = sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/gologin")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("succesfully connect to dabase")
	app := fiber.New()

	////////////////////////to make uid //////////////////////

	//app.Use(requestid.New())
	//fmt.Println(c.GetRespHeader("X-Request-Id"))

	///////////////////////
	app.Use("/loginSuccess", jwtware.New(jwtware.Config{

		SigningKey: jwtware.SigningKey{Key: []byte(jwtSecret)},
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "*",
		AllowHeaders: "*",
	}))

	app.Post("/signup", func(c *fiber.Ctx) error {

		user := Signup{}
		err := c.BodyParser(&user) //check if json
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		if user.Username == "" || user.Password == "" {
			return fiber.ErrUnprocessableEntity
		}
		fmt.Println(user)

		password, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
		}

		user.Password = string(password)
		fmt.Println(user)

		query := "insert user (username, password) values (?, ?)"
		insert, err := db.Exec(query, user.Username, user.Password)
		if err != nil {
			fmt.Println("fail to insert to db")
			return err
		}

		id, err := insert.LastInsertId()
		fmt.Println(id)
		if err != nil {
			return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
		}

		response := User{
			Id:       int(id),
			Username: user.Username,
			Password: user.Password,
		}

		return c.Status(fiber.StatusCreated).JSON(response)
	})

	app.Post("/login", func(c *fiber.Ctx) error {

		request := Login{}
		err = c.BodyParser(&request)
		if err != nil {
			return err
		}

		if request.Username == "" || request.Password == "" {
			return fiber.ErrUnprocessableEntity
		}

		if err != nil {
			return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
		}
		//fmt.Println(request)
		user := User{}
		query := "SELECT id, username, password from user WHERE username = ?"
		//rows, err := db.Query("SELECT id, username, password from user WHERE username = '" + request.Username + "'")
		err = db.QueryRow(query, request.Username).Scan(&user.Id, &user.Username, &user.Password)
		if err != nil {
			fmt.Println("cant find in database")
			return err
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
		if err != nil {
			fmt.Println("Incorrect password or username")
			return err
		}

		/*
			claims := &jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
				Issuer:    strconv.Itoa(user.Id),
			}
		*/
		//either way, second from documentastion

		claims := jwt.MapClaims{
			"id":  strconv.Itoa(user.Id),
			"exp": time.Now().Add(time.Hour * 72).Unix(),
		}
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		token, err := jwtToken.SignedString([]byte(jwtSecret))
		if err != nil {
			return fiber.ErrInternalServerError
		}

		fmt.Println(token)

		return c.JSON(fiber.Map{ //return json in map format
			"token": token,
		})

	})

	app.Get("/loginSuccess", func(c *fiber.Ctx) error {
		fmt.Println(c.Get("token"))
		req := User{}
		err := c.BodyParser(&req)
		if err != nil {
			return err
		}
		return c.SendString("welcome mr " + req.Username)
	})

	app.Listen(":5000")
	fmt.Println("server established")

}
func fiberEg() {
	app := fiber.New(fiber.Config{
		Prefork: false, //spawns multiple processes if true
	})
	////////// Middleware/pipeline control all path//////////////////////
	/*
			app.Use(func(c *fiber.Ctx) error {
				c.Locals("name", "bond") //send name through locals
				fmt.Println("run before routing is called")
				err := c.Next()
				fmt.Println("run after routing is done")
				return err
			})
			////////// Middleware control specifivc path//////////////////////
			app.Use("/get", func(c *fiber.Ctx) error {
				fmt.Println("run before specific routing is called")
				err =: c.Next()
				fmt.Println("run after specific routing is done")
				return err
			})

		// app.Use(requestid.New()); //middleware to make new uid for user

			////////////////////need to use cors if request id ////////////////////////////

		app.Use(cors.New(cors.Config{
			AllowOrigins: "*",
			AllowMethods: "*",
			AllowHeaders: "*",
		}))
	*/

	/* //////////////////Middleor micrservice using group ////////localhost/v1/"path"
	v1 := app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")  //set header
		return c.Next()
	})
					//test path localhost/v1/hello
	v1.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v1")
	})
	*/

	////Middleware using mounting /////////////
	/*
		userApp := fiber.New()
		userApp.Get("/login", func(c *fiber.Ctx) error {
			return c.SendString("Login")
		})
		app.Mount("/user", userApp)
	*/

	app.Server().MaxConnsPerIP = 1 //restrict to only 1 ip conneciton

	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"IP":          c.IP(),
			"IPs":         c.IPs(),
			"OriginalURL": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocol":    c.Protocol(),
			"Subdomains":  c.Subdomains(),
		})
	})

	//can listen to same port diffeernt method
	app.Post("/get", func(c *fiber.Ctx) error {
		return c.SendString("Posting")
	})
	//same routing different method
	app.Get("/get", func(c *fiber.Ctx) error {
		//return error if error exist
		//name := c.Locals("name") //get name from locals
		return c.SendString("getting")
	})

	//multiple params
	app.Get("/hello/:name/:surname", func(c *fiber.Ctx) error {
		name := c.Params("name")
		surname := c.Params("surname")
		return c.SendString("name: " + name + ", surname: " + surname)
	})

	//check for specific variable type
	app.Get("/hello/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}
		return c.SendString(fmt.Sprintf("ID = %v", id))
	})

	//query?name="..&id=".."
	app.Get("/query", func(c *fiber.Ctx) error {
		name := c.Query("name")
		id := c.Query("id")
		return c.SendString("result from query " + name + " id " + id)
	})

	//query directly added to struct return as json
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		fmt.Println(person)
		return c.JSON(person) //need field Json inorder to return this method
	})

	app.Get("/lineparser/*", func(c *fiber.Ctx) error {
		lineparse := c.Params("*")
		return c.SendString(lineparse)
	})

	app.Get("/error", func(c *fiber.Ctx) error {
		fmt.Println("error")
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	//psot method body

	app.Post("/body", func(c *fiber.Ctx) error {
		fmt.Println(c.Is("json")) //check fi it s json
		//person := map[string]interface{}{} // json object mapping by map/
		person := Person{} //json object mappinbg by struct
		err := c.BodyParser(&person)
		if err != nil { //check header if it s json file or no
			fmt.Println(err)
			return err
		}
		fmt.Println(person)
		fmt.Printf("%T\n", person) //tyype
		return c.JSON(person)
		//////////////////////////check field name properly //////////////////////
	})

	app.Listen(":5000")
	fmt.Println("server established")
}

type Person struct {
	Id   int    `json:"id"` //json and variable can be differnt names
	Name string `json:"name"`
}
