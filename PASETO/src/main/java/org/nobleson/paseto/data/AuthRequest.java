package org.nobleson.paseto.data;


import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class AuthRequest {
    private String username;
    private String password;
}
