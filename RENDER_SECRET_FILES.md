# Render Secret Files Setup for PodNet Identity Server

This guide shows how to use Render's Secret Files to store the identity server keypair securely.

## Option 1: Let Identity Server Generate Keypair (Recommended)

This is the simplest approach - just point to a secret file location and let the identity server generate and store the keypair.

### Steps:

1. **Deploy your identity server** with this environment variable:
   ```
   IDENTITY_KEYPAIR_FILE=/etc/secrets/identity-keypair.json
   PODNET_SERVER_URL=https://your-main-podnet-server.onrender.com
   ```

2. **First startup**: The identity server will generate a new keypair and save it to the specified path.

3. **Create a secret file** from the generated keypair:
   - Check your service logs for the generated keypair JSON
   - Go to your Render service → Environment → Secret Files
   - Create a new secret file:
     - **Filename**: `identity-keypair.json`
     - **Contents**: Copy the JSON from the logs
   - Save and redeploy

4. **Future startups**: The identity server will load the keypair from the secret file.

## Option 2: Pre-create Keypair Locally

If you want to generate the keypair locally first:

### Steps:

1. **Generate keypair locally**:
   ```bash
   # Run the identity server locally once to generate a keypair
   cargo run -p podnet-ident-strawman
   # This creates identity-server-keypair.json
   ```

2. **Create secret file in Render**:
   - Go to your Render service → Environment → Secret Files
   - Create a new secret file:
     - **Filename**: `identity-keypair.json`
     - **Contents**: Copy the contents of your local `identity-server-keypair.json`
   - Save

3. **Configure environment variable**:
   ```
   IDENTITY_KEYPAIR_FILE=/etc/secrets/identity-keypair.json
   PODNET_SERVER_URL=https://your-main-podnet-server.onrender.com
   ```

4. **Deploy**: Your identity server will use the pre-created keypair.

## Benefits

- **Secure**: Keypairs stored in Render's encrypted secret files
- **Persistent**: Survives service restarts and deployments
- **Simple**: No additional services or API tokens needed
- **Consistent**: Same identity across deployments

## Troubleshooting

### File Not Found
- Verify the secret file is named exactly `identity-keypair.json`
- Check that `IDENTITY_KEYPAIR_FILE` points to `/etc/secrets/identity-keypair.json`
- Ensure you've redeployed after creating the secret file

### Keypair Format Issues
- The secret file should contain valid JSON in the `IdentityServerKeypair` format
- Check service logs for detailed error messages
- You can delete the secret file to regenerate a new keypair

### Local Development
For local development, just use the default behavior (no environment variables needed) and the keypair will be stored locally.