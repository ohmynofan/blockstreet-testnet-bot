package utils

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"math/big"

	"github.com/google/go-querystring/query"
)

func GenerateRandomAmount(min, max float64, decimals int) (string, *big.Int, error) {
	minWei, err := ParseUnits(fmt.Sprintf("%f", min), decimals)
	if err != nil {
		return "?", nil, fmt.Errorf("failed to parse min amount: %w", err)
	}
	maxWei, err := ParseUnits(fmt.Sprintf("%f", max), decimals)
	if err != nil {
		return "?", nil, fmt.Errorf("failed to parse max amount: %w", err)
	}

	rangeSize := new(big.Int).Sub(maxWei, minWei)
	if rangeSize.Cmp(big.NewInt(0)) <= 0 {
		return "?", nil, fmt.Errorf("max must be greater than min")
	}

	randomFactor, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return "?", nil, err
	}

	amountInWei := new(big.Int).Add(minWei, randomFactor)
	amountFormatted := FormatUnits(amountInWei, decimals)

	return amountFormatted, amountInWei, nil
}

func FormatObject(obj interface{}) (string, error) {
	loggableMap := make(map[string]interface{})

	v := reflect.ValueOf(obj)

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {

		jsonOutput, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return "", err
		}
		return string(jsonOutput), nil
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if field.Kind() == reflect.Func {

			loggableMap[fieldType.Name] = "<function>"
			continue
		}

		if field.CanInterface() {
			loggableMap[fieldType.Name] = field.Interface()
		}
	}

	jsonOutput, err := json.MarshalIndent(loggableMap, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonOutput), nil
}

func Debug(data any) {
	panic(fmt.Sprintf("DEBUG DATA: %+v", data))
}

func EncodeURLParams(params interface{}) (string, error) {
	v, err := query.Values(params)
	if err != nil {
		return "", fmt.Errorf("failed to encode url param: %w", err)
	}
	return v.Encode(), nil
}

func BeautifyJSON(data []byte) string {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return string(data)
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(pretty)
}

func GenerateRandomHex(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("size must be positive")
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(buf), nil
}
