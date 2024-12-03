// Function to update the dropdown color
function updateDropdownColor(selectElement) {
    const stage = selectElement.value;

    // Reset background and text colors
    selectElement.style.backgroundColor = "";
    selectElement.style.color = "";

    if (stage === "Pending") {
        selectElement.style.backgroundColor = "#ffffff";
        selectElement.style.color = "#000000";
    } else if (stage === "InProgress") {
        selectElement.style.backgroundColor = "#ffff00";
        selectElement.style.color = "#000000";
    } else if (stage === "Solved") {
        selectElement.style.backgroundColor = "#4CAF50";
        selectElement.style.color = "#ffffff";
    }
}

// Function to load CSV data into a specific table
function loadCSV(filePath, tableBody) {
    return fetch(filePath)
        .then((response) => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.text();
        })
        .then((csvText) => {
            const results = Papa.parse(csvText, { header: true });

            if (!results.data || results.data.length === 0) {
                console.error(`No data in file ${filePath} or invalid format.`);
                return;
            }

            results.data.forEach((row) => {
                if (row.ID && row.Name && row.Stage) {
                    const tr = document.createElement("tr");
                    
                    tr.innerHTML = `
                        <td>${row.ID}</td>
                        <td>${row.Name}</td>
                        <td>
                            <select data-id="${row.ID}">
                                <option value="Pending" ${
                                    row.Stage === "Pending" ? "selected" : ""
                                }>Pending</option>
                                <option value="InProgress" ${
                                    row.Stage === "InProgress" ? "selected" : ""
                                }>InProgress</option>
                                <option value="Solved" ${
                                    row.Stage === "Solved" ? "selected" : ""
                                }>Solved</option>
                            </select>
                        </td>
                    `;
                    tableBody.appendChild(tr);

                    const selectElement = tr.querySelector("select");
                    updateDropdownColor(selectElement);
                }
            });
        })
        .catch((error) => {
            console.error(`Error loading file ${filePath}:`, error);
        });
}

// Function to save data to a specific CSV file
function saveCSV(filename, tableSelector) {
    const rows = Array.from(document.querySelectorAll(`${tableSelector} tbody tr`));
    const data = rows.map((row) => ({
        ID: row.children[0].textContent.trim(),
        Name: row.children[1].textContent.trim(),
        Stage: row.children[2].querySelector("select").value, // Lấy giá trị từ dropdown
    }));

    fetch(`/update_csv/${filename}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(data), // Gửi dữ liệu dạng JSON
    })
        .then((response) => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then((result) => {
            console.log(result.message);
            showToast(`Data saved successfully for ${filename}`);
        })
        .catch((error) => {
            console.error(`Error saving file ${filename}:`, error);
            showToast(`Error saving file ${filename}`, true);
        });
}


// Load CSV files into their respective tables
loadCSV("/static/3AD_result_failed.csv", document.querySelector("#todoTable5 tbody"));
loadCSV("/static/abc_formatted.csv", document.querySelector("#todoTable6 tbody"));
loadCSV("/static/DC3_AD_fail.csv", document.querySelector("#todoTable7 tbody"));

// Add event listener to save data when dropdown changes
document.body.addEventListener("change", (event) => {
    if (event.target.tagName === "SELECT") {
        const selectElement = event.target;
        updateDropdownColor(selectElement);

        // Determine which table the change occurred in and save the correct CSV file
        if (selectElement.closest("#todoTable5")) {
            saveCSV("3AD_result_failed.csv", "#todoTable5");
        } else if (selectElement.closest("#todoTable6")) {
            saveCSV("abc_formatted.csv", "#todoTable6");
        } else if (selectElement.closest("#todoTable7")) {
            saveCSV("DC3_AD_fail.csv", "#todoTable7");
        } 
    }
});

// Function to handle table display based on dropdown selection
function handleTableDisplay(selectedValue) {
    const tableWrappers = {
        todoTable5: document.getElementById("todoTable5Wrapper"),
        todoTable6: document.getElementById("todoTable6Wrapper"),
        todoTable7: document.getElementById("todoTable7Wrapper"),
    };

    if (selectedValue === "all") {
        // Show all tables
        Object.values(tableWrappers).forEach((wrapper) => {
            wrapper.style.display = "block";
        });
    } else {
        // Show only the selected table
        Object.entries(tableWrappers).forEach(([key, wrapper]) => {
            wrapper.style.display = key === selectedValue ? "block" : "none";
        });
    }
}

// Add dropdown functionality to switch between tables
document.getElementById("tableSelector").addEventListener("change", (event) => {
    handleTableDisplay(event.target.value);
});

// Default to showing all tables
handleTableDisplay("all");

// Function to show toast notifications
function showToast(message, isError = false) {
    const toastContainer = document.getElementById("toast-container");

    // Create new toast
    const toast = document.createElement("div");
    toast.className = `toast ${isError ? "toast-error" : ""}`;
    toast.textContent = message;

    // Add toast to container
    toastContainer.appendChild(toast);

    // Auto-remove after 3.5 seconds
    setTimeout(() => {
        toast.remove();
    }, 3500);
}

// Function to filter table rows by stage
function filterByStage(stage) {
    const allRows = document.querySelectorAll("#todoTables tbody tr");

    allRows.forEach((row) => {
        const stageValue = row.querySelector("select").value;
        if (stage === "all" || stageValue === stage) {
            row.style.display = ""; // Show row
        } else {
            row.style.display = "none"; // Hide row
        }
    });
}

// Add event listener to stage filter dropdown
document.getElementById("stageFilter").addEventListener("change", (event) => {
    const selectedStage = event.target.value;
    filterByStage(selectedStage);
});

// Default to showing all rows
filterByStage("all");
