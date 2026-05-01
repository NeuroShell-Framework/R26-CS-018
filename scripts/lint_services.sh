#!/bin/bash

# Script to lint and fix linting issues in all NeuroShell services
# This script runs ruff (linting and fixing) and black (formatting) on each service

set -e  # Exit on any error

# Get the project root directory (parent of scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# List of service directories relative to project root
SERVICES=(
    "apps/services/adaptive-execution-error-recovery"
    "apps/services/ai-vulnerability-analysis"
    "apps/services/dynamic-planner-rag"
    "apps/services/intent-recognition"
)

echo "NeuroShell Services Linting Script"
echo "Project root: $PROJECT_ROOT"
echo "Services to lint: ${#SERVICES[@]}"
echo

# Function to run a command and check for errors
run_command() {
    local cmd="$1"
    local cwd="$2"
    echo "Running: $cmd"
    echo "In directory: $cwd"
    if ! (cd "$cwd" && eval "$cmd"); then
        echo "Error: Command failed: $cmd"
        return 1
    fi
    echo
}

# Function to lint a single service
lint_service() {
    local service_path="$1"
    local service_name="$(basename "$service_path")"

    echo "=================================================="
    echo "Linting service: $service_name"
    echo "Path: $service_path"
    echo "=================================================="
    echo

    local full_path="$PROJECT_ROOT/$service_path"

    if [ ! -d "$full_path" ]; then
        echo "Warning: Service directory $full_path does not exist"
        return 1
    fi

    local success=true

    # Run ruff check
    echo "Running ruff check..."
    if ! run_command "ruff check --show-fixes ." "$full_path"; then
        success=false
    fi

    # Run ruff fix
    echo "Running ruff fix..."
    if ! run_command "ruff check --fix ." "$full_path"; then
        success=false
    fi

    # Run black
    echo "Running black..."
    if ! run_command "black ." "$full_path"; then
        success=false
    fi

    if [ "$success" = true ]; then
        echo "✓ Service $service_name linted successfully"
    else
        echo "✗ Service $service_name had linting issues"
    fi

    echo
    return 0  # Don't exit on individual service failures
}

# Main execution
main() {
    local all_success=true

    for service in "${SERVICES[@]}"; do
        if ! lint_service "$service"; then
            all_success=false
        fi
    done

    echo "=================================================="
    if [ "$all_success" = true ]; then
        echo "✓ All services linted successfully!"
        exit 0
    else
        echo "✗ Some services had linting issues. Please review the output above."
        exit 1
    fi
}

# Run main function
main