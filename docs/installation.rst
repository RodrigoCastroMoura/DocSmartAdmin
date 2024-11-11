Installation
===========

Requirements
-----------
* Python 3.8 or higher
* PostgreSQL database
* Required Python packages (see requirements.txt)

Setup
-----
1. Clone the repository
2. Install dependencies:

   .. code-block:: bash

      pip install -r requirements.txt

3. Configure environment variables:

   .. code-block:: bash

      export FLASK_APP=app.py
      export FLASK_ENV=development

4. Initialize the database:

   .. code-block:: bash

      flask db upgrade

5. Run the application:

   .. code-block:: bash

      flask run
