package org.nobleson.paseto.data;

import lombok.*;
import org.nobleson.paseto.enums.Role;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class RegistrationRequest {
    private String userID;
    private String email;
    private String username;
    private String password;
    private String otherName;
    private String surname;
    private String phone;
    private Role role;
}
