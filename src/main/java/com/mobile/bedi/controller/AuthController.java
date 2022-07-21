package com.mobile.bedi.controller;
import com.mobile.bedi.entity.User;
import com.mobile.bedi.repository.dto.TokenDto;
import com.mobile.bedi.repository.dto.UserRequestDto;
import com.mobile.bedi.service.UserService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.security.GeneralSecurityException;

@Slf4j
@AllArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    @PostMapping ("/google")
    public ResponseEntity<TokenDto> googleAuthorize(@RequestBody UserRequestDto userRequestDto) throws GeneralSecurityException, IOException {
        User user = userService.signup(userRequestDto.getCredential());

        return ResponseEntity.ok(userService.login(user));
    }

    @GetMapping ("/user")
    public ResponseEntity<String> getUserInfo() {
        User finduser = userService.getUserWithAuthorities().get();
        System.out.println(finduser.getName());
        return ResponseEntity.ok(finduser.getName());
    }

}
