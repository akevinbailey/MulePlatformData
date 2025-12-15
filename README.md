# Mule Platform Data
This project is a collection of examples on how to extract various types of data form the MuleSoft Anypoint Platform APIs.
### --- WARNING ---
All the content of this project is for example purposes only, and has not been fully tested. Under no circumstance should this code be run in a production environment.

## MuleOnboardTime.py:  Calculate API onboarding time in MuleSoft Anypoint Platform.
### User story 
As a project manager, I want to know the time between when an API specification is loaded into Anypoint Exchange and when the MuleSoft API specification implementation goes into production in API Manager, so that I can calculate the time it takes to onboard an API.  I also want to know the maximum and average times.
- Since this is an API specification the definition of production is when the API is published in the API Manager production environment (PROD)
- For large numbers of APIs, this report will need to use page sizes to limit the number of APIs returned on each call and requires additional calls for each page.