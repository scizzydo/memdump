/*
	MIT License

	Copyright (c) 2023 scizzydo http://github.com/scizzydo/memdump

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#pragma once
#include <iostream>
#include <format>

// Series of functions to just handle the 'logging' to the stdout
namespace logging {

enum class colors {
	none,
	black,
	red,
	green,
	yellow,
	blue,
	magenta,
	cyan,
	white,
	bright_black,
	bright_red,
	bright_green,
	bright_yellow,
	bright_blue,
	bright_magenta,
	bright_cyan,
	bright_white,
};

const char* to_color_code(colors c);

void print(colors c, std::string_view str);
void print(colors c, std::wstring_view str);

template <typename... Args>
void print(colors c, std::wstring_view fmt, Args&&... args) {
	print(c, std::vformat(fmt, std::make_wformat_args(args...)));
}

template <typename... Args>
void print(colors c, std::string_view fmt, Args&&... args) {
	print(c, std::vformat(fmt, std::make_format_args(args...)));
}

template<typename... Args>
void success(std::string_view fmt, Args&&... args) {
	print(colors::green, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void info(std::string_view fmt, Args&&... args) {
	print(colors::cyan, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void error(std::string_view fmt, Args&&... args) {
	print(colors::red, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void success(std::wstring_view fmt, Args&&... args) {
	print(colors::green, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void info(std::wstring_view fmt, Args&&... args) {
	print(colors::cyan, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void error(std::wstring_view fmt, Args&&... args) {
	print(colors::red, fmt, std::forward<Args>(args)...);
}

};
