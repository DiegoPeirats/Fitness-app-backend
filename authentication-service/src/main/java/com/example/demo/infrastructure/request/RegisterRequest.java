package com.example.demo.infrastructure.request;

public record RegisterRequest(
		String email,
		String password,
		String name
	) {

}
