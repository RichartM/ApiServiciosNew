package com.example.PaseListaApi.auth.service;


import com.example.PaseListaApi.auth.model.AuthDetails;
import com.example.PaseListaApi.model.user_info.User_infoRepository;
import com.example.PaseListaApi.model.user_info.Users_info;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthDetailsService implements UserDetailsService {
    private final User_infoRepository user_infoRepository;

    public AuthDetailsService(User_infoRepository user_infoRepository) {
        this.user_infoRepository = user_infoRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users_info userAccount = user_infoRepository.findByEmail(username);
        if (userAccount == null) {
            throw new UsernameNotFoundException(username);
        }
        return new AuthDetails(userAccount);
    }
}
