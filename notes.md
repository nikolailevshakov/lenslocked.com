

# users.go
const userPwPepper = "secret-random-string"
const hmacSecretKey = "secret-hmac-key"

# services.go
db, err := gorm.Open("postgres", connectionInfo)
if err != nil {
  return nil, err
}
db.LogMode(true)
