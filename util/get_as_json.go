package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// 簡略化のためHTTPリクエストを送信し、レスポンスをJSONとして指定の型にUnmarshalする関数
func GetAsJson(url string, value interface{}) error {
	fmt.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("can't send request to %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("can't read body: %v", err)
	}

	err = json.Unmarshal(body, value)
	if err != nil {
		return fmt.Errorf("can't unmarshal json: %v", err)
	}

	return nil
}
