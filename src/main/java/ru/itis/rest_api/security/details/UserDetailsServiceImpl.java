package ru.itis.rest_api.security.details;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import ru.itis.rest_api.models.Token;
import ru.itis.rest_api.repositories.TokensRepository;

import java.util.function.Supplier;

@Component("tokenUserDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private TokensRepository tokensRepository;

    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String token) throws UsernameNotFoundException {
        Token result = tokensRepository.findByRefreshToken(token).orElseThrow((Supplier<Throwable>) () -> new UsernameNotFoundException("Token not found"));
        return new UserDetailsImpl(result.getUser());
    }

}
