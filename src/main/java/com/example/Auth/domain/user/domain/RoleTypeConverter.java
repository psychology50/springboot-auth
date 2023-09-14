package com.example.Auth.domain.user.domain;

import com.example.Auth.global.common.utils.converter.AbstractLegacyEnumAttributeConverter;
import jakarta.persistence.Convert;

@Convert
public class RoleTypeConverter extends AbstractLegacyEnumAttributeConverter<RoleType> {
    private static final String ENUM_NAME = "유저권한";

    public RoleTypeConverter() {
        super(RoleType.class, false, ENUM_NAME);
    }
}
