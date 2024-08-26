package com.neotys.TwoFactorAuth;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TOTPCodeGeneartorActionTest {
	@Test
	public void shouldReturnType() {
		final TOTPCodeGeneartorAction action = new TOTPCodeGeneartorAction();
		assertEquals("TOTPCodeGeneartor", action.getType());
	}

}
