package main

import (
    "html/template"
    "database/sql"
    "log"
    _"fmt"
    "net/http"
    "io"
    "os"

    "github.com/gorilla/sessions"
    "github.com/labstack/echo-contrib/session"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

type Templates struct {
    templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
    return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
    return &Templates{
        templates: template.Must(template.ParseGlob("frontend/templates/*.html")),
    }
}

type User struct {
    Username string
    Password string
}

func getAllUsers() ([]User, error) {
    db, err := sql.Open("sqlite3", "eve.db")
    if err != nil {
        return nil, err
    }
    defer db.Close()

    rows, err := db.Query("SELECT username, password FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(&user.Username, &user.Password)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}


func createTable() {
    db, err := sql.Open("sqlite3", "eve.db")
    if err != nil {
        log.Fatalf("Database connection error: %v", err)
    }
    defer db.Close()

    query := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
    `
    _, err = db.Exec(query)
    if err != nil {
        log.Fatalf("Error creating table: %v", err)
    }
}
func userExists(username string) (bool, error){
    db, err := sql.Open("sqlite3", "eve.db")
    if err != nil {
        return false, err
    }
    defer db.Close()

    var exists bool
    query := "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? LIMIT 1)"
    err = db.QueryRow(query, username).Scan(&exists)
    if err != nil {
        return false, err
    }
    return exists, nil
}
func insertUser(username, password string) error {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    db, err := sql.Open("sqlite3", "eve.db")
    if err != nil {
        return err
    }
    defer db.Close()

    _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
    return err
}


func matchUserPassword(username, password string) (bool, error) {
    user, err := getUserByUsername(username)
    if err != nil {
        return false, err
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
    if err != nil {
        return false, nil
    }
    return true, nil

}


func getUserByUsername(username string) (User, error) {
    db, err := sql.Open("sqlite3", "eve.db")
    if err != nil {
        return User{}, err
    }
    defer db.Close()

    //avoid pointers; use indexes instead

    var currUser User

    err = db.QueryRow("SELECT username, password FROM users WHERE username = ?", username).Scan(&currUser.Username, &currUser.Password)
    if err != nil {
        return User{}, err
    }

    return currUser, nil
}


func main() {
    cert := os.Getenv("CF_CERT_PATH")
    key := os.Getenv("CF_KEY_PATH")

    if cert == "" || key == "" {
        log.Fatal("CF_CERT_PATH and CF_KEY_PATH must be set")
    }

    createTable()

    e := echo.New()
    e.Renderer = newTemplate()
    e.Logger.SetLevel(3)

    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret-key"))))
    go func() {
        e := echo.New()
        e.GET("/*", func(c echo.Context) error {
            return c.Redirect(http.StatusMovedPermanently, "https://"+c.Request().Host+c.Request().RequestURI)
        })
        e.Logger.Fatal(e.Start(":80"))
    }()



    e.GET("/", func(c echo.Context) error {
        return c.Render(http.StatusOK, "index.html", nil)
    })

    e.GET("/login-form", func(c echo.Context) error {
        return c.Render(http.StatusOK, "login-form.html", nil)
    })

    e.GET("/register-form", func(c echo.Context) error {
        return c.Render(http.StatusOK, "register-form.html", nil)
    })

    e.GET("/user-land", func(c echo.Context) error {
        sess, _ := session.Get("session", c)
        username := sess.Values["username"]
        if username == nil {
            return c.Redirect(http.StatusMovedPermanently, "/")
        }
        return c.Render(http.StatusOK, "user-land.html", map[string]interface{}{
            "Username": username,
        })
    })

    e.GET("/logout", func(c echo.Context) error {
        sess, _ := session.Get("session", c)
        sess.Options.MaxAge = -1
        sess.Save(c.Request(), c.Response())
        return c.Redirect(http.StatusMovedPermanently, "/")
    })

    var monster = map[string]interface{}{
        "MonsterName": "Adult Black Dragon",
        "MonsterHealth": "100",
        "MonsterAC": "20",
        "MonsterAttackRoll": "10",
        "MonsterDamage": "2d6+4",
    }

    e.GET("/monster/1/edit", func(c echo.Context) error {
        return c.Render(http.StatusOK, "monsterEdit.html", monster)
    })

    e.PUT("/monster/1", func(c echo.Context) error {
        monster["MonsterName"] = c.FormValue("monsterName")
        monster["MonsterHealth"] = c.FormValue("monsterHealth")
        monster["MonsterAC"] = c.FormValue("monsterAC")
        monster["MonsterAttackRoll"] = c.FormValue("monsterAttackRoll")
        monster["MonsterDamage"] = c.FormValue("monsterDamage")

        return c.Render(http.StatusOK, "displayMonster.html", monster)
    })

    e.GET("/monster/1", func(c echo.Context) error {
        return c.Render(http.StatusOK, "displayMonster.html", monster)
    })




    e.POST("/register", func(c echo.Context) error {
        username := c.FormValue("username")
        password := c.FormValue("password")

        exists, err := userExists(username)
        if err != nil {
            return err
        }

        if exists {
            return c.Render(http.StatusOK, "partials.html", map[string]interface{}{
                "Message": "User already exists",
                "MessageType": "error",
        })
    }

        err = insertUser(username, password)
        if err != nil {
            return err
        }
            return c.Render(http.StatusOK, "partials.html", map[string]interface{}{
            "Message": "User created successfully",
        })
    })

    e.GET("/login", func(c echo.Context) error {
        return c.Redirect(http.StatusMovedPermanently, "/user-land")
    })

    e.POST("/login", func(c echo.Context) error {
        username := c.FormValue("username")
        password := c.FormValue("password")

        valid, err := matchUserPassword(username, password)
        if err != nil {
            return c.Render(http.StatusOK, "partials.html", map[string]interface{}{
                "Message": "Error logging in. Please try again",
                "MessageType": "error",
                "targetID": "#login-error",
                "swapID": "outerHTML",
            })
        }

        if !valid {
            return c.Render(http.StatusOK, "partials.html", map[string]interface{}{
                "Message": "Invalid username or password! Please try again",
                "MessageType": "error",
                "targetID": "#login-error",
                "swapID": "outerHTML",
            })
        }

        sess, _ := session.Get("session", c)
        sess.Values["username"] = username
        sess.Save(c.Request(), c.Response())

        return c.Render(http.StatusOK, "user-land.html", map[string]interface{}{
            "Username": username,
        })
    })




    e.Logger.Fatal(e.StartTLS(":443", cert, key))
}

