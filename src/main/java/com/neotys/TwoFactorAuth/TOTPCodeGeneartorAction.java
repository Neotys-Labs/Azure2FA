package com.neotys.TwoFactorAuth;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import com.google.common.base.Optional;
import com.neotys.extensions.action.Action;
import com.neotys.extensions.action.ActionParameter;
import com.neotys.extensions.action.ActionParameter.Type;
import com.neotys.extensions.action.engine.ActionEngine;

public final class TOTPCodeGeneartorAction implements Action{
	private static final String BUNDLE_NAME = "com.neotys.TwoFactorAuth.bundle";
	private static final String DISPLAY_NAME = ResourceBundle.getBundle(BUNDLE_NAME, Locale.getDefault()).getString("displayName");
	private static final String DISPLAY_PATH = ResourceBundle.getBundle(BUNDLE_NAME, Locale.getDefault()).getString("displayPath");
	private static final ImageIcon LOGO_ICON = new ImageIcon(TOTPCodeGeneartorAction.class.getResource("icons8-key-50.png"));

	@Override
	public String getType() {
		return "TOTPCodeGeneartor";
	}

	@Override
	public List<ActionParameter> getDefaultActionParameters() {
		final List<ActionParameter> parameters = new ArrayList<ActionParameter>();
		parameters.add(new ActionParameter("SecretKey","Eneter the Secretkey from your application",Type.PASSWORD));
		// TODO Add default parameters.
		return parameters;
	}

	@Override
	public Class<? extends ActionEngine> getEngineClass() {
		return TOTPCodeGeneartorActionEngine.class;
	}

	@Override
	public Icon getIcon() {
		// TODO Add an icon
		//return null;
		return LOGO_ICON;
	}

	@Override
	public boolean getDefaultIsHit(){
		return false;
	}

	@Override
	public String getDescription() {
		final StringBuilder description = new StringBuilder();
		// TODO Add description
		description.append("TOTPCodeGeneartor description.\n");
		description.append("This action allows you to genearte TOTP code for Microsoft & google Two factor authentication.\n Parameters:\n");
		description.append("SecretKey: The Secretkey  received from your application post registering the user \n");

		return description.toString();
	}

	@Override
	public String getDisplayName() {
		return DISPLAY_NAME;
	}

	@Override
	public String getDisplayPath() {
		return DISPLAY_PATH;
	}

	@Override
	public Optional<String> getMinimumNeoLoadVersion() {
		return Optional.absent();
	}

	@Override
	public Optional<String> getMaximumNeoLoadVersion() {
		return Optional.absent();
	}
}
