package com.example.demo.application.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.application.response.TokenResponse;
import com.example.demo.domain.entity.Token;
import com.example.demo.domain.entity.User;
import com.example.demo.infrastructure.repository.TokenRepository;
import com.example.demo.infrastructure.repository.UserRepository;
import com.example.demo.infrastructure.request.LoginRequest;
import com.example.demo.infrastructure.request.RegisterRequest;

@Service
public class AuthService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JwtService jwtService;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	
	public TokenResponse registerUser(RegisterRequest request) {
		User user = new User(request.name(), request.email(), passwordEncoder.encode(request.password()));
		User savedUser = userRepository.save(user);
		String jwtToken = jwtService.generateToken(user);
		String refreshToken = jwtService.generateRefreshToken(user);
		saveUserToken(savedUser, jwtToken);
		
		return new TokenResponse(jwtToken, refreshToken);
	}
	
	public TokenResponse login(LoginRequest request) {
		
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.email(),
						request.password())
				);
		User user = userRepository.findByEmail(request.email())
				.orElseThrow(() -> new IllegalStateException("Email not found"));
		String jwtToken = jwtService.generateToken(user);
		String refreshToken = jwtService.generateRefreshToken(user);
		revokeAllUserTokens(user);
		saveUserToken(user, jwtToken);
		return new TokenResponse(jwtToken, refreshToken);
	}
	
	private void revokeAllUserTokens(User user) {
		List<Token> validUserTokens = tokenRepository
				.findAllValidTokenByUser(user.getId());
		if (!validUserTokens.isEmpty()) {
			for (Token token : validUserTokens) {
				token.setExpired(true);
				token.setRevoked(true);
			}
			tokenRepository.saveAll(validUserTokens);
		}
		
	}

	private void saveUserToken(User user, String jwtToken) {
		Token token = new Token(jwtToken, Token.TokenType.BEARER, false, false, user);
		
		tokenRepository.save(token);
	}
	
	public TokenResponse refreshToken(String authHeader) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			throw new IllegalArgumentException("Invalid Bearer token");
		}
		
		String refreshToken = authHeader.substring(7);
		String userEmail = jwtService.extractUsername(refreshToken);
		
		if (userEmail == null) {
			throw new IllegalArgumentException("invalid Refresh Token");
		}
		
		User user = userRepository.findByEmail(userEmail)
				.orElseThrow(() -> new UsernameNotFoundException(userEmail));
		
		if (!jwtService.isTokenValid(refreshToken, user)) {
			throw new IllegalArgumentException("Invalid Refresh Token");
			
		}
		
		String accessToken = jwtService.generateToken(user);
		revokeAllUserTokens(user);
		saveUserToken(user, accessToken);
		return new TokenResponse(accessToken, refreshToken);
	}

}
