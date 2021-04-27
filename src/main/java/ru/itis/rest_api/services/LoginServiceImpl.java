package ru.itis.rest_api.services;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.itis.rest_api.dto.EmailPasswordDto;
import ru.itis.rest_api.dto.TokenDto;
import ru.itis.rest_api.models.Token;
import ru.itis.rest_api.models.User;
import ru.itis.rest_api.repositories.TokensRepository;
import ru.itis.rest_api.repositories.UsersRepository;
import ru.itis.rest_api.security.token.TokensUtil;

import java.util.UUID;
import java.util.function.Supplier;

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private UsersRepository usersRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokensRepository tokensRepository;

    @SneakyThrows
    @Override
    public TokenDto login(EmailPasswordDto emailPassword) {
        User user = usersRepository.findByEmail(emailPassword.getEmail())
                .orElseThrow((Supplier<Throwable>) () -> new UsernameNotFoundException("User not found"));
        if (passwordEncoder.matches(emailPassword.getPassword(), user.getHashPassword())) {
            // String tokenValue = UUID.randomUUID().toString();
            TokensUtil tokensUtil = new TokensUtil(user);
            Token token = Token.builder()
                    .refreshToken(tokensUtil.getRefreshToken())
                    .user(user)
                    .tokensUtil(tokensUtil)
                    .time_of_creating(tokensUtil.getRefreshTime())
                    .build();

            tokensRepository.save(token);


            return TokenDto.builder()
                    .token("ACCESS: " + tokensUtil.getAccessToken() + " " + "REFRESH: " + tokensUtil.getRefreshToken())
                    .build();
        } else {
            throw new UsernameNotFoundException("Invalid username or password");
        }
    }

}
