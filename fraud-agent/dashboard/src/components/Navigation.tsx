import { NavLink } from "react-router-dom"
import {
  ChartBarIcon,
  ShieldAlertIcon,
  DocumentTextIcon,
  Cog6ToothIcon,
} from "@heroicons/react/24/outline"

const navigation = [
  { name: "Dashboard", href: "/dashboard", icon: ChartBarIcon },
  { name: "Detections", href: "/detections", icon: ShieldAlertIcon },
  { name: "Reports", href: "/reports", icon: DocumentTextIcon },
  { name: "Settings", href: "/settings", icon: Cog6ToothIcon },
]

export default function Navigation() {
  return (
    <nav className="flex space-x-1 p-1 bg-gray-100 rounded-lg">
      {navigation.map((item) => (
        <NavLink
          key={item.name}
          to={item.href}
          className={({ isActive }) =>
            `flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
              isActive
                ? "bg-white text-primary-600 shadow-sm"
                : "text-gray-600 hover:text-gray-900 hover:bg-gray-200"
            }`
          }
        >
          <item.icon className="w-5 h-5 mr-2" />
          {item.name}
        </NavLink>
      ))}
    </nav>
  )
}