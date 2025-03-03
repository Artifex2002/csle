import React from 'react';
import './TransmittedDroppedChart.css';
import {
    CartesianGrid,
    Label,
    Legend, Line,
    LineChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis
} from "recharts";


/**
 * Component containing a plot showing the average number of dropped transmitted packets over time
 */
const TransmittedDroppedChart = React.memo((props) => {
        const width = 500
        const height = 200
        const margin = {
            top: 10,
            right: 30,
            left: 60,
            bottom: 25
        }

        if (props.stats !== undefined && props.stats.length > 0) {
            var minTransmittedDropped = 1000000000000
            var maxTransmittedDropped = 0
            const data = props.stats.map((port_stats, index) => {
                if (parseInt(port_stats.total_num_transmitted_dropped) < minTransmittedDropped){
                    minTransmittedDropped = parseInt(port_stats.total_num_transmitted_dropped)
                }
                if (parseInt(port_stats.total_num_transmitted_dropped) > maxTransmittedDropped){
                    maxTransmittedDropped = parseInt(port_stats.total_num_transmitted_dropped)
                }
                return {
                    "t": (index + 1),
                    "Transmitted dropped frames": parseInt(port_stats.total_num_transmitted_dropped)
                }
            })
            var domain = [0, Math.max(1, data.length)]
            var yDomain = [minTransmittedDropped, maxTransmittedDropped]

            return (
                <ResponsiveContainer width='100%' height={300}>
                    <LineChart
                        width={width}
                        height={height}
                        data={data}
                        margin={margin}
                    >
                        <CartesianGrid strokeDasharray="3 3"/>
                        <XAxis dataKey="t" type="number" domain={domain}>
                            <Label value="Time-step t" offset={-20} position="insideBottom" className="largeFont"/>
                        </XAxis>
                        <YAxis type="number" domain={yDomain}>
                            <Label angle={270} value="# Transmitted dropped frames" offset={-50} position="insideLeft"
                                   className="largeFont"
                                   dy={50}/>
                        </YAxis>
                        <Tooltip/>
                        <Legend verticalAlign="top" wrapperStyle={{position: 'relative', fontSize: '15px'}}
                                className="largeFont"/>
                        <Line isAnimationActive={props.animation} animation={props.animation} type="monotone"
                              dataKey="Transmitted dropped frames"
                              stroke="#8884d8" addDot={false} activeDot={{r: 8}}
                              animationEasing={'linear'}
                              animationDuration={((1 - (props.animationDuration / 100)) * props.animationDurationFactor)}/>
                    </LineChart>
                </ResponsiveContainer>
            )

        } else {
            return (
                <div></div>
            )
        }
    }
)
TransmittedDroppedChart.propTypes = {};
TransmittedDroppedChart.defaultProps = {};
export default TransmittedDroppedChart;
