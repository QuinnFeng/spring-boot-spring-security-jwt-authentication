package com.bezkoder.springjwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(), 
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {
    if (userRepository.existsByUsername(user.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(user.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User u = new User(user.getUsername(), 
               user.getEmail(),
               encoder.encode(user.getPassword()));


    userRepository.save(u);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
  
  @PostMapping("/addRole")
  @Transactional
  public ResponseEntity<?> addRolesToUser(@RequestParam String username, @RequestParam String role) {
      // Find user by username
      User user = userRepository.findByUsername(username)
              .orElseThrow(() -> new RuntimeException("Error: User not found."));

      // Convert role string to enum safely
      ERole er;
      try {
          er = ERole.valueOf("ROLE_" + role.toUpperCase());
      } catch (IllegalArgumentException e) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid role!"));
      }

      // Find role entity
      Role roleToAdd = roleRepository.findByName(er)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

      // Check if the user already has the role
      if (user.getRoles().contains(roleToAdd)) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: User already has the role '" + role + "'!"));
      }

      // Add the new role and save
      user.getRoles().add(roleToAdd);
      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("Role '" + role + "' added successfully!"));
  }
  
  @DeleteMapping("/removeRole")
  @Transactional
  public ResponseEntity<?> removeRoleFromUser(@RequestParam String username, @RequestParam String role) {
      // Find user by username
      User user = userRepository.findByUsername(username)
              .orElseThrow(() -> new RuntimeException("Error: User not found."));

      // Convert role string to enum safely
      ERole er;
      try {
          er = ERole.valueOf("ROLE_" + role.toUpperCase());
      } catch (IllegalArgumentException e) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid role!"));
      }

      // Find role entity
      Role roleToRemove = roleRepository.findByName(er)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

      // Check if the user has the role before removing
      if (!user.getRoles().contains(roleToRemove)) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: User does not have the role '" + role + "'!"));
      }

      // Remove the role and save the user
      user.getRoles().remove(roleToRemove);
      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("Role '" + role + "' removed successfully!"));
  }

}
