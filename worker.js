export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.slice(1); // Remove leading slash

      if (!path.includes('/')) {
        return new Response('Invalid archive path', { status: 400 });
      }

      // Compute the same hash as the mirror script
      const encoder = new TextEncoder();
      const data = encoder.encode(path); // Hash the path without scheme
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Construct the image name using the same format as mirror.py
      const imageName = `url-sha256-${hashHex}`;
      const baseUrl = `${env.REGISTRY_URL}/v2/${env.NAMESPACE}/${imageName}`;

      // Fetch the manifest from GitHub Container Registry
      const manifestUrl = `${baseUrl}/manifests/latest`;

      const manifestResponse = await fetch(manifestUrl, {
        headers: {
          'Accept': 'application/vnd.oci.image.manifest.v1+json',
          'Authorization': `Bearer QQ==`,
        }
      });

      if (!manifestResponse.ok) {
        return new Response(`Image ${imageName} not found`, {
          status: 404,
          headers: {
            'Content-Type': 'text/plain'
          }
        });
      }

      const manifest = await manifestResponse.json();

      // Get the first (and only) layer from the manifest
      if (!manifest.layers || manifest.layers.length !== 1) {
        return new Response(`Not exactly one layer in manifest ${imageName}:latest`, { status: 500 });
      }

      const layer = manifest.layers[0];
      const layerDigest = layer.digest;

      // Fetch the layer blob (the actual archive file)
      const blobUrl = `${baseUrl}/blobs/${layerDigest}`;

      const blobResponse = await fetch(blobUrl, {
        headers: {
          'Authorization': `Bearer QQ==`,
        }
      });

      if (!blobResponse.ok) {
        return new Response(`Failed to fetch archive blob ${layerDigest}`, { status: 500 });
      }

      // Extract filename from original URL for Content-Disposition header
      const urlParts = path.split('/');
      const filename = urlParts[urlParts.length - 1];

      // Return the archive with appropriate headers
      const response = new Response(blobResponse.body, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': blobResponse.headers.get('Content-Length'),
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control': 'public, max-age=31536000, immutable', // Cache for 1 year
        }
      });

      return response;

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(`Internal server error: ${error.message}`, { status: 500 });
    }
  }
};