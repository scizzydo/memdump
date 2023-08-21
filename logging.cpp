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

#include "logging.hpp"

#include <chrono>

#include "misc.h"

namespace logging {
	const char* to_color_code(colors c) {
		switch (c) {
		case colors::black:
			return "\033[0;30m";
		case colors::red:
			return "\033[0;31m";
		case colors::green:
			return "\033[0;32m";
		case colors::yellow:
			return "\033[0;33m";
		case colors::blue:
			return "\033[0;34m";
		case colors::magenta:
			return "\033[0;35m";
		case colors::cyan:
			return "\033[0;36m";
		case colors::white:
			return "\033[0;37m";
		case colors::bright_black:
			return "\033[0;90m";
		case colors::bright_red:
			return "\033[0;91m";
		case colors::bright_green:
			return "\033[0;92m";
		case colors::bright_yellow:
			return "\033[0;93m";
		case colors::bright_blue:
			return "\033[0;94m";
		case colors::bright_magenta:
			return "\033[0;95m";
		case colors::bright_cyan:
			return "\033[0;96m";
		case colors::bright_white:
			return "\033[0;97m";
		default:
			return "\033[0m";
		}
	}

	void print(colors c, std::string_view str) {
		// This feels dirty, but when mapping in the exe to the other, I get access violations with chrono
		FILETIME file_time_now{}, file_time_local_now{};
		GetSystemTimeAsFileTime(&file_time_now);
		FileTimeToLocalFileTime(&file_time_now, &file_time_local_now);
		SYSTEMTIME system_time{};
		FileTimeToSystemTime(&file_time_local_now, &system_time);
		std::cout << to_color_code(c) << std::format("[{:02d}:{:02d}:{:02d}.{:06d}]: ",
			system_time.wHour, system_time.wMinute, system_time.wSecond, system_time.wMilliseconds)
			<< str << "\033[0m" << std::endl;
	}

	void print(colors c, std::wstring_view str) {
		print(c, wstring_to_string(str.data()));
	}
}
