package com.neotys.TwoFactorAuth;

import java.util.List;

import com.neotys.extensions.action.ActionParameter;
import com.neotys.extensions.action.engine.ActionEngine;
import com.neotys.extensions.action.engine.Context;
import com.neotys.extensions.action.engine.SampleResult;
import com.warrenstrange.googleauth.GoogleAuthenticator;

public final class TOTPCodeGeneartorActionEngine implements ActionEngine {

	@Override
	public SampleResult execute(Context context, List<ActionParameter> parameters) {
		final SampleResult sampleResult = new SampleResult();
		final StringBuilder requestBuilder = new StringBuilder();
		final StringBuilder responseBuilder = new StringBuilder();
		 String secret = "";
		sampleResult.sampleStart();

		appendLineToStringBuilder(requestBuilder, "TOTPCodeGeneartor request.");
		appendLineToStringBuilder(responseBuilder, "TOTPCodeGeneartor response.");
		// TODO perform execution.
		
		GoogleAuthenticator gAuth = new GoogleAuthenticator();

        // Generate a key if you don't have one
       /* GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();
        System.out.println("Secret: " + secret);
*/		try {	
				for(ActionParameter parameter:parameters) {

					switch(parameter.getName()) {
						case "SecretKey":
							secret = parameter.getValue();
						break;			
					}
              }
		       
		        // Use the secret to generate the TOTP code
		        
		        appendLineToStringBuilder(requestBuilder,"Generating the code using seceret key"+"\n");
		        int code = gAuth.getTotpPassword(secret);
		        System.out.println("TOTP Code: " + code);
		        appendLineToStringBuilder(responseBuilder,"<Code>"+code+"</Code>"+"\n");
		        sampleResult.sampleEnd();
				
	}
    catch (Exception e)
    {
      //  System.out.println(e);
    	sampleResult.sampleEnd();

		sampleResult.setRequestContent(requestBuilder.toString());
		sampleResult.setResponseContent(responseBuilder.toString());
        return getErrorResult(context, sampleResult, e.getMessage(), e);
    }
		sampleResult.setRequestContent(requestBuilder.toString());
		sampleResult.setResponseContent(responseBuilder.toString());
		return sampleResult;
	}
     
	private void appendLineToStringBuilder(final StringBuilder sb, final String line){
		sb.append(line).append("\n");
	}

	/**
	 * This method allows to easily create an error result and log exception.
	 */
	private static SampleResult getErrorResult(final Context context, final SampleResult result, final String errorMessage, final Exception exception) {
		result.setError(true);
		result.setStatusCode("NL-TOTPCodeGeneartor_ERROR");
		result.setResponseContent(errorMessage);
		if(exception != null){
			context.getLogger().error(errorMessage, exception);
		} else{
			context.getLogger().error(errorMessage);
		}
		return result;
	}

	@Override
	public void stopExecute() {
		// TODO add code executed when the test have to stop.
	}

}
