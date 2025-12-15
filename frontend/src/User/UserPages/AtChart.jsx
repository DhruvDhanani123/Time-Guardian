import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import { Chart } from "chart.js/auto";
import chartStyle from "./AtChart.module.css";

const AtChart = () => {
  const [userData, setUserData] = useState([]);
  const username = localStorage.getItem("username");
  const chartRef = useRef(null); // Create a ref to store the chart instance

  useEffect(() => {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 7);

    axios
      .get(
        `http://localhost:5000/chartdata?username=${username}&startDate=${startDate.toISOString()}&endDate=${endDate.toISOString()}`
      )
      .then((response) => {
        setUserData(response.data);
      })
      .catch((error) => {
        console.error(error);
      });
  }, [username]);

  useEffect(() => {
    // Once userData is loaded, create or update the chart
    if (userData.length > 0) {
      const ctx = chartRef.current.getContext("2d");

      // Destroy previous chart (if it exists)
      if (chartRef.current.chart) {
        chartRef.current.chart.destroy();
      }

      // Create new chart
      chartRef.current.chart = new Chart(ctx, {
        type: "bar",
        data: {
          labels: userData.map((user) => user.day),
          datasets: [
            {
              label: `Working Time(MIN)`,
              data: userData.map((user) => user.duration),
              backgroundColor: "#D4ADFC",
              borderColor: "#4E31AA",
              borderWidth: 1,
            },
          ],
        },
        options: {
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                font: {
                  size: "12",
                  weight: "bold",
                },
                color: "#FF5733",
              },
            },
            x: {
              ticks: {
                font: {
                  size: "12",
                  weight: "bold",
                },
                color: "#00C851",
              },
            },
          },
        },
      });
    }
  }, [userData]);

  return (
    <>
      <div className="overflow-x-auto">
        <div className={`container mt-5 mx-auto ${chartStyle.chart}`}>
          <canvas id="myChart" ref={chartRef}></canvas>
        </div>
      </div>
    </>
  );
};

export default AtChart;
