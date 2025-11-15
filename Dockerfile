FROM mcr.microsoft.com/powershell:7.4-alpine-3.20

# Metadata
LABEL maintainer="PowerShield Project"
LABEL description="PowerShield - Comprehensive PowerShell Security Analysis Platform"
LABEL version="1.6.0"

# Note: Git should be installed in the runtime environment if incremental analysis is needed
# Example: docker run --rm -v $(pwd):/workspace powershield analyze /workspace

# Set working directory
WORKDIR /app

# Copy PowerShield files
COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY psts.ps1 /app/psts.ps1
COPY psts /app/psts

# Make psts executable
RUN chmod +x /app/psts /app/psts.ps1

# Set entrypoint to PowerShell with psts.ps1
ENTRYPOINT ["pwsh", "/app/psts.ps1"]

# Default command: show help
CMD ["help"]
