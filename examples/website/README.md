# Exoware Simulator Web UI Example

This example provides a basic web interface built with React to interact with the Exoware Simulator. It demonstrates how to use the `@exoware/sdk-ts` to connect to and interact with the `store` and `stream` modules of the simulator.

## Prerequisites

- Node.js and npm
- Rust and Cargo

## How to Run

1.  **Start the Simulator:**

    Open a terminal in the root of the monorepo and run the following command to start the simulator. You can choose any auth token.

    ```bash
    cargo run --package exoware-simulator -- server run --auth-token your-secret-token
    ```

2.  **Update Auth Token in the UI:**

    Open `examples/website/src/App.tsx` and replace `'your-secret-token'` in the `AUTH_TOKEN` constant with the token you used to start the simulator.

    ```typescript
    const AUTH_TOKEN = 'your-secret-token'; // IMPORTANT: Replace with your actual auth token
    ```

3.  **Install Dependencies and Run the Web App:**

    Navigate to the `examples/website` directory and install the dependencies, then start the development server.

    ```bash
    # from the root of the monorepo
    cd examples/website
    npm install
    npm run dev
    ```

4.  **Open the Web UI:**

    Open your browser and navigate to the URL provided by Vite (usually `http://localhost:5173`). You should see the UI for interacting with the simulator.

## Features

-   **Store:**
    -   Set a key-value pair.
    -   Get a value by key.
    -   Query for a range of keys.
-   **Stream:**
    -   Publish messages to a named stream.
    -   Subscribe to a named stream and see messages in real-time.
