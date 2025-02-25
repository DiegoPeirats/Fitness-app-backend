package com.example.demo.infrastructure.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PruebaController {
	
	
	@GetMapping("prueba")
	private String prueba() {
		return "Prueba exitosa";
	}

}
