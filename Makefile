.PHONY: help format format-check build clean

BUILD_DIR ?= build-local

help:
	@echo "  make format        Format C++ with clang-format"
	@echo "  make format-check  Check formatting without modifying files"
	@echo "  make build         Configure and build with CMake ($(BUILD_DIR))"
	@echo "  make clean         Remove $(BUILD_DIR)"

CXX_FILES := $(shell git ls-files '*.cpp' '*.h')

format:
	clang-format -i $(CXX_FILES)

format-check:
	clang-format --dry-run --Werror $(CXX_FILES)

build:
	cmake -S . -B $(BUILD_DIR) 
	cmake --build $(BUILD_DIR) -j

clean:
	rm -rf $(BUILD_DIR)
