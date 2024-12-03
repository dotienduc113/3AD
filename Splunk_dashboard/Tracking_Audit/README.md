
# Tracking_Audit

Tracking_Audit is a JavaScript-based web application designed to assist users in monitoring and updating the status of failed items in the `Tracking_List` of Domain Controllers (DCs) under active monitoring. This tool provides a convenient way to track and manage audit statuses directly through an interactive interface.

---

## Features

- **CSV Integration**: Automatically loads CSV files containing the tracking list for failed items from multiple Domain Controllers.
- **Status Update**: Enables users to change the status of items (`Failed`, `In Progress`, or `Resolved`) directly in the interface.
- **Real-Time Updates**: Reflects changes in the tracking list instantly without needing to refresh the page.
- **User-Friendly Interface**: Simple and intuitive design for seamless operation.

---

## Installation

Follow the steps below to set up the application locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/HieuVu2402/Tracking_Audit.git
   cd Tracking_Audit
   ```

2. Ensure you have a local server running (e.g., Python, Node.js, or any HTTP server).

3. Start the server. For example, using Python:
   ```bash
   python -m http.server
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

---

## Usage

1. Place the tracking list CSV files (`3AD_result_failed.csv`, `DC3_AD_fail.csv`, etc.) in the `static` folder.
2. Open the application in your browser.
3. View and edit the statuses directly in the interface:
   - Click on the dropdown to select the new status for an item.
   - The changes will be reflected in real time.

---

## File Structure

```
Tracking_Audit/
│
├── static/
│   ├── 3AD_result_failed.csv       # Tracking list for Domain Controller 3AD
│   ├── DC3_AD_fail.csv             # Tracking list for Domain Controller DC3
│   ├── script.js                   # JavaScript logic for handling user interactions
│   ├── style.css                   # CSS for styling the interface
│   └── papaparse.min.js            # Library for parsing CSV files
│
├── templates/
│   └── index.html                  # Main HTML file for the application
│
├── app.py                          # Optional Python server file (if required)
└── README.md                       # Documentation file
```

---

## Technologies Used

- **JavaScript**: Core logic and user interaction handling.
- **HTML & CSS**: User interface design and styling.
- **PapaParse**: Library for handling CSV parsing.

---

## Contributing

Contributions are welcome! Feel free to:
- Report bugs.
- Suggest new features.
- Create pull requests.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.

---

## Contact

If you have any questions or feedback, feel free to reach out:
- **Author**: Hieu Vu
- **Email**: hieu.vu@example.com
