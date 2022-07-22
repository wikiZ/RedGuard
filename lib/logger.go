/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: logger.go
 * @Time: 2022/5/5 9:09
 **/

package lib

import "github.com/phachon/go-logger"

func Logger() *go_logger.Logger {
	logger := go_logger.NewLogger()
	if err := logger.Detach("console"); err != nil {
		return nil
	}
	console := &go_logger.ConsoleConfig{
		Color:  true, // Whether the text shows color
		Format: "[%timestamp_format%] %body%",
	}
	fileConfig := &go_logger.FileConfig{
		Filename:  "./RedGuard.log",
		MaxSize:   1024 * 1024, // Maximum file size (KB). The default value is 0
		MaxLine:   50000,
		MaxBak:    1,
		DateSlice: "d",
		Format:    "[%timestamp_format%] [%function%] %body%",
	}
	logger.Attach("file", go_logger.LOGGER_LEVEL_DEBUG, fileConfig)
	logger.Attach("console", go_logger.LOGGER_LEVEL_DEBUG, console)
	return logger
}
